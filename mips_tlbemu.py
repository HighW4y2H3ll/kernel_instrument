#!/usr/bin/env python3

import sys
import unicorn

kseg0 = 0x80000000
size = 0x1000000


def translate(mem, vaddr, debug=False):
    def hook_block(uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

    def hook_code(uc, address, size, user_data):
        if debug:
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
        if debug:
            print("K0: 0x%x, K1: 0x%x" %(mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K0), mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K1)))

    try:
        mach = unicorn.Uc(unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_32+unicorn.UC_MODE_LITTLE_ENDIAN)
        mach.mem_map(kseg0, size)
        mach.mem_write(kseg0, mem)
        #mach.reg_write(unicorn.mips_const.UC_MIPS_REG_PC, kseg0)
        if debug:
            mach.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)
        mach.hook_add(unicorn.UC_HOOK_CODE, hook_code)
        mach.emu_start(kseg0, kseg0+size)
        if debug:
            print("Done")
        k0 = mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K0)
        k1 = mach.reg_read(unicorn.mips_const.UC_MIPS_REG_K1)
        PFN0 = (k0>>6)<<12
        PFN1 = (k1>>6)<<12
        if debug:
            print("K0: 0x%x, K1: 0x%x, PFN0: 0x%x, PFN1: 0x%x" %(k0, k1, PFN0, PFN1))
        off = vaddr&0xfff
        if (vaddr>>12)%2 == 0:
            if debug:
                print("PFN: 0x%x, PA: 0x%x" %(PFN0, PFN0+off))
            pfn = PFN0
        else:
            if debug:
                print("PFN: 0x%x, PA: 0x%x" %(PFN1, PFN1+off))
            pfn = PFN1
        if pfn != 0:
            return pfn+off
        else:
            return 0
    except unicorn.UcError as e:
        if debug:
            print(e)


if __name__ == '__main__':
    mem = sys.argv[1]
    vaddr = int(sys.argv[2], 16)
    with open(mem, 'rb') as fd:
        print("PA: 0x%x" %translate(fd.read(), vaddr, True))
