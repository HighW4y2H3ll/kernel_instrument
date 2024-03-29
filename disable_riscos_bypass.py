#!/usr/bin/python3

import vm
import re
import os
import sys
os.environ['LIBCAPSTONE_PATH'] = os.path.join(os.path.dirname(__file__), "capstone")

import keystone.bindings.python.keystone as keystone
import capstone.bindings.python.capstone as capstone

# however, kernel image on Raspberry Pi is stripped-header raw image, we lost all the relocation info (virtual address mapping).
# The good part is we have a complete physical memory dump and register info. Thus, we can recover the memory mapping by re-walking the page table.


# https://www.riscosopen.org/wiki/documentation/show/HAL%20OS%20layout%20and%20headers
# /Source/Kernel/hdr/OSEntries
# RISC OS rom image format:
# 0 ~ 0x10000       HAL
# 0x10000           OS image base

# Regards to the Risc OS source code syntax, Ref: http://www.riscos.com/support/developers/asm/index.html
# And also: https://www.riscosopen.org/wiki/documentation/show/A%20BASIC%20guide%20to%20ObjAsm

# NOTE: Risc OS overrides undefined instruction vector for floating point instruction emulation at a later stage of bootstrap
# the location of instrumentation (`breakpoints`) should be chosen carefully, so that the time when breakpoints are reached,
# the undefined instruction vector should be already patched to the FPE (floating point emulation) handler
# also NOTE: that conditional flag bits might also affected, so should not instrument at `tst`, `cmp` instructions etc.


def patching(raw, offset, patch, addr=0):
    encoding, count = ks.asm(patch.encode(), addr)
    print([hex(c) for c in encoding])
    print(len(encoding))
    print(count)
    origin_bytes = raw[offset:offset+len(encoding)]
    print(origin_bytes)
    return (encoding, origin_bytes)

def b2pat(bstr):
    return b"".join(["\\x{:02x}".format(c).encode('latin-1') for c in bstr])

def align(va, alignment=4):
    ra = (va+alignment-1)&(~(alignment-1))
    return ra, ra-va


# e.g. `./patch_riscos.py riscpi.reg riscpi.mem RISCOS.IMG 0x30000000 new.img`
if len(sys.argv) < 5:
    print("Usage: patch.py [reg file] [mem dump] [kernel img] [min log storage vaddr]")
    sys.exit()

kernel_base = int(sys.argv[4], 16)
print("kernel base: ", hex(kernel_base))
with open(sys.argv[3], 'rb') as fd:
    kernel_data = fd.read()
mm = vm.VM(sys.argv[1], sys.argv[2])
vma = mm.walk()

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM|capstone.CS_MODE_LITTLE_ENDIAN)

und_off = 4
und_va = None
main_patch_vaddr = None
main_patch_off = None
main_patch_size  = 0
storage_vaddr = None
storage_size = 0
for va, pa, sz, prot in vma:
    if va == 0xffff0000:
        excp_vec = mm._read(pa, 0x20)
        for i in cs.disasm(excp_vec, 0):
            print(i)
        #print(hex(mm._read_word(mm.translate(0xffff0018+8+0x418))))
        #for i in cs.disasm(mm._read(mm.translate(0xfc012900), 0x20), 0xfc012900):
        #    print(i)
        #sys.exit()
        i = next(cs.disasm(excp_vec[4:8], va + und_off))   # entry for _und
        print(i, hex(pa))
        if (i.mnemonic == "b"): # Linux
            und_va = int(i.op_str[1:], 16)
            possible_patch = [m.start() for m in re.finditer(excp_vec, kernel_data)]
            assert(len(possible_patch) == 1)
        elif (i.mnemonic == "ldr"): # RiscPi
            print(i.op_str)
            op = re.search("pc, \[pc, #(0x[0-9a-fA-F]+)\]", i.op_str).group(1)
            print(op)
            und_va = mm._read_word(mm.translate(i.address+8+int(op,16)))
            print(hex(und_va))
            und_va = mm._read_word(pa+i.address-va+8+int(op,16))
            print("addr: ", hex(und_va), hex(mm.translate(und_va)))
            i = next(cs.disasm(mm._read(mm.translate(und_va), 4), und_va))
            print (" => ", i)
            assert (i.mnemonic == "ldr")
            op = re.search("pc, \[pc, #(0x[0-9a-fA-F]+)\]", i.op_str).group(1)
            print(op)
            und_va = mm._read_word(mm.translate(i.address)+8+int(op,16))
            print("addr: ", hex(und_va), hex(mm.translate(und_va)))
            i = next(cs.disasm(mm._read(mm.translate(und_va), 4), und_va))
            print (" ==> ", i)
            assert (i.mnemonic == "ldr")
            op = re.search("pc, \[pc, #((0x)?[\-0-9a-fA-F]+)\]", i.op_str).group(1)
            print(op)
            assert ("0x" not in op)
            und_va = mm._read_word(mm.translate(i.address)+8+int(op))
            print("addr: ", hex(und_va), hex(mm.translate(und_va)))
    if prot.check_exec() and va > kernel_base:
        page = mm._read(pa, sz)
        for nullpad in re.finditer(b"(\xff+)", page):
            # bid for the largest null padding
            if len(nullpad.group()) > 0x100 and main_patch_size < len(nullpad.group()):
                print("exec: ", [hex(va+x) for x in nullpad.span()])
                sig = mm._read(pa, nullpad.start())
                koff = kernel_data.find(sig)
                print(len(sig))
                print(hex(koff))
                if len(sig) > 0 and koff != -1:
                    main_patch_off, adj = align(koff+nullpad.start())
                    main_patch_size = len(nullpad.group()) - adj
                    main_patch_vaddr = va+nullpad.start() + adj
    # hopefully, something safe
    if prot.check_write() and va > kernel_base and ((va^kernel_base)>>24) == 0:
        page = mm._read(pa, sz)
        for nullpad in re.finditer(b"(\x00+)", page):
            if len(nullpad.group()) > 0x100 and storage_size < len(nullpad.group()):
                print("data: ", [hex(va+x) for x in nullpad.span()])
                storage_vaddr, adj = align(va+nullpad.start())
                storage_size = len(nullpad.group()) - adj

assert(und_va)
# RiscOS:      va       ->   pa         ->   kernel img offset
#              0xfc000000    0x3bb00000      0
#              0xfc4f3b30    0x3bff3b30      0x4f3b30               : End of ROM Image (\xff) padding (for 2/4/6/8 MB alignment)
print("patch exec: ", hex(main_patch_vaddr), hex(mm.translate(main_patch_vaddr)))

# Find initial und handler to patch a trampline
und_handle = None
und_off = mm.translate(und_va)
print(hex(und_off))
sig = mm._read(und_off, 0x1000)
for i in cs.disasm(sig, und_va):
    print (i)
    # check when overwrites pc
    if i.op_str.startswith("pc,"):
        sig = sig[:i.address-und_va+i.size]
        break

und_kernimg_off = None
for match in re.finditer(b2pat(sig), kernel_data):
    print([hex(x) for x in match.span()])
    assert (not und_kernimg_off)
    und_kernimg_off = match.start()
assert(und_kernimg_off)
print(hex(und_kernimg_off))

#sys.exit()

# Start patching
patchset = {}
ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM|keystone.KS_MODE_LITTLE_ENDIAN)

# Define breakpoints
usb = 0xfc207944
breakpoints = [usb]
smi = 0xfc2356c4
breakpoints = [smi]

oldbytes = []
for bp in breakpoints:
    kern_off = None
    off = mm.translate(bp)
    print(hex(off))
    sig = mm._read(off, 0x20)

    # Fixing for Linux, avoid `bl __gnu_mcount_nc`, which is dynamically patched to `ldm sp!, {lr}` in memory dump
    for i in cs.disasm(sig, bp):
        print(i)
        if i.mnemonic == "ldm" and i.op_str == "sp!, {lr}":
            sig = sig[:i.address-bp]
            break

    print(b2pat(sig))
    for match in re.finditer(b2pat(sig), kernel_data):
        print(" >", hex(bp), " : ", [hex(x) for x in match.span()])
        # page offset should match with the virtual address
        if match.start()&mm.page_mask(bp) == bp&mm.page_mask(bp) or \
                (0x8000+match.start())&mm.page_mask(bp) == bp&mm.page_mask(bp): # Raspi kernel base might starts at 0x8000
            assert (not kern_off)   # should have only one match
            kern_off = match.start()
    # some might not be aligned (e.g. RiscOS)
    if not kern_off:
        for match in re.finditer(b2pat(sig), kernel_data):
            print(" >>", hex(bp), " : ", [hex(x) for x in match.span()])
            assert (not kern_off)
            kern_off = match.start()

    assert (kern_off)   # should find the match now
    oldbytes.append(",".join([hex(c) for c in kernel_data[kern_off:kern_off+4]]))
    print("DEBUG")
    print(oldbytes[-1])
    print(kernel_data[kern_off:kern_off+4])
    patchset[kern_off] = patching(kernel_data, kern_off, ".word 0xe7fddef1")
    #patchset[kern_off+4] = patching(kernel_data, kern_off+4, "b $.;")

#sys.exit()

# Patch und excp stub
# patch excp_und dispatch table: __und_svc
#patch_off = vector_base_off + 4
#patchset[patch_off] = patching(binary_data, patch_off, "b $+{}".format(0x12c0))
#patch_off = vector_base_off + 0x11d4    # __und_svc vector
#patchset[patch_off] = patching(kernel_data, patch_off, ".word {}".format(hex(main_patch_vaddr)))
patch_off = und_kernimg_off
patchset[patch_off] = patching(kernel_data, patch_off,
        #"b $.;"
        #"stmdb sp!, {{r0-r3}};"
        #"mrc p15, 0, r0, c1, c0, 0;"
        #"tst r0, #1;"
        "ldr pc, $.Ldispat;"
        ".Ldispat:"
        ".word {DISPATCH_VADDR};".format(
            DISPATCH_VADDR=hex(main_patch_vaddr),
            DISPATCH_PADDR=hex(mm.translate(main_patch_vaddr)),
            ), und_va)
tramp_orig_bytes = patchset[patch_off][1]
tramp_orig_rest = und_va + len(tramp_orig_bytes)

#print(hex(und_va))
#print(hex(und_kernimg_off))
#sys.exit()

# Patch main dispatcher
patch_off = main_patch_off
patchset[patch_off] = patching(kernel_data, patch_off,
        #"mrs r0, cpsr;"
        #"eor r0, r0, #8;"
        ##"orr r0, r0, #c0;"      # keep irq disabled or redisable irq
        #"msr spsr_cxsf, r0;"
        #"adr r0, .Lhandle;"
        #"movs pc, r0;"          # get back to UND mode
        #".Lhandle:"
        #"ldr r0, [sp, #8];"     # restore r0, lr, spsr
        #"msr spsr_cxsf, r0;"
        #"ldmia sp, {{r0, lr}};"

        "stmdb sp!, {{r0-r3}};"
        #"mrs r0, spsr;"
        #"and r0, r0, #0x1f;"    # check mode for those without independent SPSR
        #"teq r0, #0x10;"        # skip user
        #"beq .Lund;"
        #"teq r0, #0x1f;"        # skip system
        #"beq .Lund;"

        "adr r0, .Lbp;"         # verify breakpoints
        "ldr r1, $.Lstat;"
        "sub r2, r2, r2;"

        ".Lloop:"
        "ldr r3, [r0, r2, LSL#2];"
        "adds r3, r3, #0;"      # - check end of list (breakpoints)
        "beq .Lund;"
        "add r3, r3, #4;"       # (assume arm mode, lr will be the next inst after the breakpoint) check thumb?
        "teq r3, lr;"           # - check breakpoint match
        "beq .Lupdate;"
        "add r2, r2, #1;"
        "b .Lloop;"

        ".Lupdate:"             # update hit counter
        "add r3, r1, r2, LSL#2;"
        ".Lretrylog:"
        "ldrex r1, [r3];"
        "add r1, r1, #1;"
        "strex r0, r1, [r3];"   # check failed?
        "tst r0, r0;"
        "bne .Lretrylog;"
        "cmp r1, #{BYPASSCNT};"
        "bhs .Ldisable;"

        "ldr r0, $.Lstorage;"
        "mrc p15, 0, r1, c0, c0, 5;"    # read MPIDR to get core number
        "and r1, r1, #15;"
        "add r0, r0, r1, LSL#2;"
        ".Lretrystub:"
        "ldrex r3, [r0];"
        "strex r3, lr, [r0];"   # store return address, check cpu id?
        "tst r3, r3;"
        "bne .Lretrystub;"
        "adr lr, .Lstub;"       # start restore
        "add lr, lr, r2, LSL#3;"# find stub (@r2: bp index)
        "ldmia sp!, {{r0-r3}};"
        "movs pc, lr;"          # trigger context switch

        ".Lrestore:"            # restore original control flow
        "sub sp, sp, #4;"
        "stmdb sp, {{r0-r1}};"
        "ldr r0, $.Lstorage;"
        "mrc p15, 0, r1, c0, c0, 5;"    # read MPIDR to get core number
        "and r1, r1, #15;"
        "add r0, r0, r1, LSL#2;"
        "ldrex r0, [r0];"       # atomic load
        "clrex;"                # clear execution monitor
        #"sub r4, r4, r4; ldr r4, [r4];"    # page fault debug
        "str r0, [sp];"
        "ldmdb sp, {{r0-r1}};"
        "ldmia sp!, {{pc}};"

        ".Lund:"                # und faulting - have to restore the original und_excp handler here
        "ldmia sp!, {{r0-r3}};" # Linux init proc invokes und inst on boot, probably breakpoint setup
        ".byte {ORIG_UND_VEC};"
        "ldr pc, [pc, #-4];"
        ".word {ORIG_UND_REST};"
        "b $.;"
        ".Ldisable:"
        "adr lr, .Ldisablestub;"       # start restore
        "ldmia sp!, {{r0-r3}};"
        "movs pc, lr;"          # trigger context switch
        ".Ldisablestub:"
        "bic r11, r11, #1;"     # disable IRQ
        "mov pc, lr;"

        ".Lstub:"               # stub for the original inst replaced by breakpoint
        #"mov r12, sp;"         # NOTE: at this point the only register got messed up is PC (r15),
        #"b .Lrestore;"         #       be careful with PC relative load/store/branch etc.
        "{STUB}"
        ".Lstorage:"            # storage of lr reg for context switch, no worry if original inst mess up with registers
        ".word {LR_STORAGE};"   # - one should make sure there are enough space (one reg_size(4 bytes) for each cpu core)
        ".Lstat:"               # address to store stat info
        ".word {STAT_STORAGE};" # - space requirement: 4 bytes per breakpoints
        ".Lbp:"                 # null-ended list of breakpoint address
        ".word {BREAKPOINTS};"
        ".word 0;".format(
                ORIG_UND_VEC=",".join([hex(c) for c in tramp_orig_bytes]),
                ORIG_UND_REST=hex(tramp_orig_rest),
                LR_STORAGE=hex(storage_vaddr),
                STAT_STORAGE=hex(storage_vaddr+0x10),
                BREAKPOINTS=",".join([hex(p) for p in breakpoints]),
                STUB="".join([".byte {};b .Lrestore;".format(b) for b in oldbytes]),
                BYPASSCNT=hex(0x800)
                )
        , main_patch_vaddr)


# Second round, We've only patched VFP emulation, Now to patch the default UNDEF
und_va = 0xfc028fe4     # Found through JTAG: mdw 0xffff0120
main_patch_vaddr += 0x400   # Another dispatcher
main_patch_off += 0x400
und_handle = None
und_off = mm.translate(und_va)
print(hex(und_off))
sig = mm._read(und_off, 0x1000)
for i in cs.disasm(sig, und_va):
    print (i)
    # check when overwrites pc
    if i.op_str.startswith("pc,"):
        sig = sig[:i.address-und_va+i.size]
        break

und_kernimg_off = None
for match in re.finditer(b2pat(sig), kernel_data):
    print([hex(x) for x in match.span()])
    assert (not und_kernimg_off)
    und_kernimg_off = match.start()
assert(und_kernimg_off)
print(hex(und_kernimg_off))

patch_off = und_kernimg_off
patchset[patch_off] = patching(kernel_data, patch_off,
        #"b $.;"
        #"stmdb sp!, {{r0-r3}};"
        #"mrc p15, 0, r0, c1, c0, 0;"
        #"tst r0, #1;"
        "ldr pc, $.Ldispat;"
        ".Ldispat:"
        ".word {DISPATCH_VADDR};".format(
            DISPATCH_VADDR=hex(main_patch_vaddr),
            DISPATCH_PADDR=hex(mm.translate(main_patch_vaddr)),
            ), und_va)
tramp_orig_bytes = patchset[patch_off][1]
tramp_orig_rest = und_va + len(tramp_orig_bytes)

patch_off = main_patch_off
patchset[patch_off] = patching(kernel_data, patch_off,
        "stmdb sp!, {{r0-r3}};"

        "adr r0, .Lbp;"         # verify breakpoints
        "sub r2, r2, r2;"

        ".Lloop:"
        "ldr r3, [r0, r2, LSL#2];"
        "adds r3, r3, #0;"      # - check end of list (breakpoints)
        "beq .Lund;"
        "add r3, r3, #4;"       # (assume arm mode, lr will be the next inst after the breakpoint) check thumb?
        "teq r3, lr;"           # - check breakpoint match
        "beq .Lupdate;"
        "add r2, r2, #1;"
        "b .Lloop;"

        ".Lupdate:"             # update hit counter

        "adr lr, .Lstub;"       # start restore
        "add lr, lr, r2, LSL#4;"# find stub (@r2: bp index)
        "ldmia sp!, {{r0-r3}};"
        "movs pc, lr;"          # trigger context switch

        ".Lund:"                # und faulting - have to restore the original und_excp handler here
        "ldmia sp!, {{r0-r3}};" # Linux init proc invokes und inst on boot, probably breakpoint setup
        ".byte {ORIG_UND_VEC};"
        "ldr pc, [pc, #-4];"
        ".word {ORIG_UND_REST};"
        "b $.;"

        ".Lstub:"               # stub for the original inst replaced by breakpoint
        #"mov r12, sp;"         # NOTE: at this point the only register got messed up is PC (r15),
        #"ldr pc, [pc, #-4];"   #       be careful with PC relative load/store/branch etc.
        #".word {BP Return Addr};"
        #"b $.;"
        "{STUB}"
        ".Lbp:"                 # null-ended list of breakpoint address
        ".word {BREAKPOINTS};"
        ".word 0;".format(
                ORIG_UND_VEC=",".join([hex(c) for c in tramp_orig_bytes]),
                ORIG_UND_REST=hex(tramp_orig_rest),
                BREAKPOINTS=",".join([hex(p) for p in breakpoints]),
                STUB="".join([".byte {};ldr pc, [pc, #-4];.word {};b $.;".format(b,r+4) for b,r in zip(oldbytes,breakpoints)])
                )
        , main_patch_vaddr)




# All Done, now output
print("storage address: ", hex(storage_vaddr))

if len(sys.argv) > 5:
    with open(sys.argv[5], 'wb') as fd:
        data = kernel_data
        for off, patch in patchset.items():
            data = data[:off] + bytes(patch[0]) + data[off+len(patch[0]):]
        fd.write(data)
