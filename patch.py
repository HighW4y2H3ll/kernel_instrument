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


# e.g. `./patch.py linux.reg linux.mem kernel7.img 0x80000000`
if len(sys.argv) < 5:
    print("Usage: patch.py [reg file] [mem dump] [kernel img] [kernel base vaddr]")
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
            und_va = mm._read_word(mm.translate(va + und_off + 8 + int(op, 16)))
    if prot.check_exec() and va > kernel_base:
        page = mm._read(pa, sz)
        for nullpad in re.finditer(b"(\x00+)", page):
            # bid for the largest null padding
            if len(nullpad.group()) > 0x200 and main_patch_size < len(nullpad.group()):
                print("exec: ", [hex(va+x) for x in nullpad.span()])
                sig = mm._read(pa, nullpad.start())
                koff = kernel_data.find(sig)
                print(len(sig))
                print(hex(koff))
                if koff != -1:
                    main_patch_off = koff+nullpad.start()
                    main_patch_size = len(nullpad.group())
                    main_patch_vaddr = va+nullpad.start()
    # hopefully, something safe
    if prot.check_write() and va > kernel_base and ((va^kernel_base)>>24) == 0:
        page = mm._read(pa, sz)
        for nullpad in re.finditer(b"(\x00+)", page):
            if len(nullpad.group()) > 0x100 and storage_size < len(nullpad.group()):
                print("data: ", [hex(va+x) for x in nullpad.span()])
                storage_vaddr, adj = align(va+nullpad.start())
                storage_size = len(nullpad.group()) - adj

assert(und_va)

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
    und_kernimg_off = match.start()
assert(und_kernimg_off)
print(hex(und_kernimg_off))

#sys.exit()

# Start patching
patchset = {}
ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM|keystone.KS_MODE_LITTLE_ENDIAN)

# Define breakpoints
breakpoints = [0x80102154, 0x8010ff9c]
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

    assert (kern_off)   # should find the match now
    oldbytes.append(",".join([hex(c) for c in kernel_data[kern_off:kern_off+4]]))
    print("DEBUG")
    print(oldbytes[-1])
    print(kernel_data[kern_off:kern_off+4])
    patchset[kern_off] = patching(kernel_data, kern_off, ".word 0xe7fddef1")

#sys.exit()

# Patch und excp stub
# patch excp_und dispatch table: __und_svc
#patch_off = vector_base_off + 4
#patchset[patch_off] = patching(binary_data, patch_off, "b $+{}".format(0x12c0))
#patch_off = vector_base_off + 0x11d4    # __und_svc vector
#patchset[patch_off] = patching(kernel_data, patch_off, ".word {}".format(hex(main_patch_vaddr)))
patch_off = und_kernimg_off
patchset[patch_off] = patching(kernel_data, patch_off,
        "ldr pc, $.Ldispat;"
        ".Ldispat:"
        ".word {};".format(hex(main_patch_vaddr)), main_patch_vaddr)
tramp_orig_bytes = patchset[patch_off][1]
tramp_orig_rest = und_va + len(tramp_orig_bytes)

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
                STUB="".join([".byte {};b .Lrestore;".format(b) for b in oldbytes])
                )
        , main_patch_vaddr)

print("storage address: ", hex(storage_vaddr))

if len(sys.argv) > 5:
    with open(sys.argv[5], 'wb') as fd:
        data = kernel_data
        for off, patch in patchset.items():
            data = data[:off] + bytes(patch[0]) + data[off+len(patch[0]):]
        fd.write(data)
