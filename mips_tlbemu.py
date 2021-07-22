#!/usr/bin/env python3

import sys
import unicorn

mem = sys.argv[1]
vaddr = int(sys.argv[2], 16)
kseg0 = 0x80000000
size = 0x1000000

def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    insn = uc.mem_read(address, size)
    if insn == b'\x18\x00\x00\x42': # eret
        uc.emu_stop()
    if address > kseg0:
        insn = uc.mem_read(address-size, size)
        if insn == b'\x00\x40\x1a\x40':   # badVaddr
            uc.reg_write(unicorn.mips_const.UC_MIPS_REG_K0, vaddr)
        elif insn == b'\x00\x20\x1a\x40':   # context
            uc.reg_write(unicorn.mips_const.UC_MIPS_REG_K0, ((vaddr>>13)<<4)&(0x7ffff0))
    print(f"K0: {hex(mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K0))}, K1: {hex(mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K1))}")

try:
    mach = unicorn.Uc(unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_32+unicorn.UC_MODE_LITTLE_ENDIAN)
    mach.mem_map(kseg0, size)
    with open(mem, 'rb') as fd:
        mach.mem_write(kseg0, fd.read())
    #mach.reg_write(unicorn.mips_const.UC_MIPS_REG_PC, kseg0)
    mach.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)
    mach.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    mach.emu_start(kseg0, kseg0+size)
    print("Done")
    k0 = mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K0)
    k1 = mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K1)
    PFN0 = (k0>>6)<<12
    PFN1 = (k1>>6)<<12
    print(f"K0: {hex(k0)}, K1: {hex(k1)}, PFN0: {hex(PFN0)}, PFN1: {hex(PFN1)}")
    if (vaddr>>12)%2 == 0:
        print(f"PFN: {hex(PFN0)}")
    else:
        print(f"PFN: {hex(PFN1)}")
except unicorn.UcError as e:
    print(e)
