#!/usr/bin/python3

import sys
import lief
import keystone


def align(addr, page_size=0x1000):
    page_mask = page_size - 1
    return (addr+page_mask)&(~page_mask)

binary = lief.parse(sys.argv[1])

def find_nullstr_len(buf, start):
    i = start + 1
    while i < len(buf):
        if buf[i] == 0:
            i += 1
        else:
            break
    return i - start

def find_null(buf, alignment=None, minpad=0x800):
    # find available space in the end of segemnt/section and the page alignemt
    if alignment:
        nslen = alignment-(len(buf)%alignment)
        if nslen > minpad:
            return (len(buf), nslen)

    off = 0
    while off < len(buf):
        if buf[off] == 0 and buf[off+1] == 0 and buf[off+2] == 0 and buf[off+3] == 0:
            nslen = find_nullstr_len(buf, off)
            if nslen > 0x10:
                print("Null str: {}:{}".format(hex(off), hex(nslen)))
            if nslen > minpad and nslen <= 0x1000:   # shoudl be enough for instrumentation
                return (off, nslen)
            off += nslen
        else:
            off += 4
    return (None, None)

def search_patch_buf(target):
    next_seg_start = 0;
    next_off_start = 0;
    #for section in binary.sections:
    #    if section.name == ".duhh":
    #        section.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.EXECINSTR
    for seg in target.segments:
        print(seg)
        if seg.virtual_address&0xffff0000 != 0xffff0000:
            next_seg_start = max(next_seg_start, align(seg.virtual_address + seg.virtual_size, seg.alignment))
        print(len(seg.content))
        if (seg.has(lief.ELF.SEGMENT_FLAGS.X)):
            off, nslen = find_null(seg.content)
            if off and nslen:
                return (seg, off, nslen)
        print(hex(seg.physical_address), hex(seg.physical_size))
        print(hex(seg.virtual_address), hex(seg.virtual_size))
        next_seg_start = max(next_seg_start, align(seg.physical_address + seg.physical_size, seg.alignment))
    
    #patch_seg = lief.ELF.Segment()
    #print(hex(next_seg_start))
    #patch_seg.virtual_address = next_seg_start
    #patch_seg.physical_address = next_seg_start
    #patch_seg.virtual_size = 0x10
    #patch_seg.physical_size = 0x10
    #patch_seg.alignment = 0x10000
    #patch_seg.add(lief.ELF.SEGMENT_FLAGS.R)
    #patch_seg.add(lief.ELF.SEGMENT_FLAGS.X)
    #patch_seg.type = lief.ELF.SEGMENT_TYPES.LOAD
    #patch_seg.file_offset = binary.eof_offset

    #patch_seg.content = [ord('a')]*0x10
    #binary.add(patch_seg)
    #print(patch_seg)
def search_section_buf(target, section):
    for seg in target.segments:
        for sec in seg.sections:
            if sec.name == section:
                print(sec)
                print(hex(sec.offset))
                off, nslen = find_null(sec.content, 0x1000)
                print(hex(sec.virtual_address+off))
                return (sec.file_offset+off, nslen)

def get_section_base_off(target, section):
    for seg in target.segments:
        for sec in seg.sections:
            if sec.name == section:
                return sec.file_offset

def get_section_vaddr_map(target, section):
    for seg in target.segments:
        for sec in seg.sections:
            if sec.name == section:
                return sec.virtual_address

#search_section_buf(binary, ".text")
seg, off, sz = search_patch_buf(binary)
main_patch_vaddr = seg.virtual_address+off
main_patch_off = seg.file_offset+off
main_patch_size = sz
print(hex(main_patch_vaddr))
print(hex(main_patch_off))
print(hex(main_patch_size))

# space after exception vectors are poinsoned at runtime, not an ideal place to static overwrite
# however, stubs (the staging trampline right after exception vectors) are not
stub_patch_off, stub_patch_size = search_section_buf(binary, ".stubs")
print(hex(stub_patch_off))
print(hex(stub_patch_size))

# overwrite undefined instruction vector entry
vector_base_off = get_section_base_off(binary, ".vectors")
vector_base_vaddr = 0xffff0000
print(hex(vector_base_off))

# find free writable places
data_off, data_size = search_section_buf(binary, ".data")
print(hex(data_off))
print(hex(data_size))

# get text offset && virtual address to instrument
inst_vaddr_base = get_section_vaddr_map(binary, ".text")
inst_off_base = get_section_base_off(binary, ".text")


# load raw data
with open(sys.argv[1], 'rb') as fd:
    binary_data = fd.read()

# define breakpoints
breakpoints = [0x80102154, 0x8010ff18]
oldbytes = []
for bp in breakpoints:
    off = bp - inst_vaddr_base + inst_off_base
    oldbytes.append(",".join([hex(c) for c in binary_data[off:off+4]]))
    print("DEBUG")
    print(oldbytes[-1])
    print(binary_data[off:off+4])

# Start patching
def patching(raw, offset, patch, addr=0):
    encoding, count = ks.asm(patch.encode(), addr)
    print([hex(c) for c in encoding])
    print(len(encoding))
    print(count)
    origin_bytes = raw[offset:offset+len(encoding)]
    print(origin_bytes)
    return (encoding, origin_bytes)

patchset = {}
ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM|keystone.KS_MODE_LITTLE_ENDIAN)
# patch excp_und dispatch table: __und_svc
#patch_off = vector_base_off + 4
#patchset[patch_off] = patching(binary_data, patch_off, "b $+{}".format(0x12c0))
patch_off = vector_base_off + 0x11d4    # __und_svc vector
patchset[patch_off] = patching(binary_data, patch_off, ".word {}".format(hex(main_patch_vaddr)))
# patch dispatcher
patch_off = main_patch_off
patchset[patch_off] = patching(binary_data, patch_off,
        "mrs r0, cpsr;"
        "eor r0, r0, #8;"
        #"orr r0, r0, #c0;"      # keep irq disabled or redisable irq
        "msr spsr_cxsf, r0;"
        "adr r0, .Lhandle;"
        "movs pc, r0;"          # get back to UND mode
        ".Lhandle:"
        "ldr r0, [sp, #8];"     # restore r0, lr, spsr
        "msr spsr_cxsf, r0;"
        "ldmia sp, {{r0, lr}};"

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

        ".Lund:"
        "ldmia sp!, {{r0-r3}};"
        "b {ORIG_UND_SVC};"

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
                ORIG_UND_SVC=hex(0x80101a00),
                LR_STORAGE=hex(0x80d03dd0),
                STAT_STORAGE=hex(0x80d03de0),
                BREAKPOINTS=",".join([hex(p) for p in breakpoints]),
                STUB="".join([".byte {};b .Lrestore;".format(b) for b in oldbytes])
                )
        , main_patch_vaddr)

# patch breakpoints
for bp in breakpoints:
    patch_off = bp - inst_vaddr_base + inst_off_base
    patchset[patch_off] = patching(binary_data, patch_off, ".word 0xe7fddef1")


if len(sys.argv) > 2:
    #binary.write(sys.argv[2])
    with open(sys.argv[2], 'wb') as fd:
        data = binary_data
        for off, patch in patchset.items():
            data = data[:off] + bytes(patch[0]) + data[off+len(patch[0]):]
        fd.write(data)
