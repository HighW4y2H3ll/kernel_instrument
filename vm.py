#!/usr/bin/python3

import struct

class ArchCpu(object):
    def load_reg(self, reg):
        raise
    def maskN(self, n):
        return (1<<n)-1

class ArmCpu(ArchCpu):
    def load_reg(self, reg):
        regs = {}
        for line in open(reg, 'r'):
            k, _, v = line.strip().split()
            regs[k] = int(v, 0)
        self.ttbr0 = regs['translation_table_base_0_0']
        self.ttbr1 = regs['translation_table_base_1_0']
        self.ttbcr = regs['translation_table_base_control_0']
        self.N = self.ttbcr&7

    def mask_ttbr0(self):
        return (self.ttbr0 & (~self.maskN(14-self.N)))

    def mask_ttbr1(self):
        return (self.ttbr1 & (~self.maskN(14)))

# Ref: https://developer.arm.com/documentation/ddi0406/cb/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors
class VM(ArchCpu):
    def __init__(self, reg, mem):
        self._fd_mem = open(mem, 'rb')

        self.cpu = ArmCpu()
        self.cpu.load_reg(reg)

    def select_base(self, va):
        if self.cpu.N == 0:
            return self.cpu.mask_ttbr0()
        # else N > 0
        if (va & (self.cpu.maskN(self.cpu.N)<<(32-self.cpu.N))) == 0:
            return self.cpu.mask_ttbr0()
        else:
            return self.cpu.mask_ttbr1()

    def _read(self, off, sz):
        self._fd_mem.seek(off)
        return self._fd_mem.read(sz)

    def _read_word(self, off):
        x = self._read(off, 4)
        return struct.unpack('<I', x)[0]

    def _level_1_table_index(self, va):
        return (va>>20)&self.cpu.maskN(12-self.cpu.N)

    def _level_2_table_index(self, va):
        return (va>>12)&self.cpu.maskN(8)

    def _translate_section(self, pd, va):
        #TODO
        raise
    def _translate_page_table(self, pd, va):
        pmd = pd&(~self.cpu.maskN(10))
        pmd += (self._level_2_table_index(va)<<2)
        return self._read_word(pmd)

    def _translate_large_page(self, pd, va):
        uh = pd&(~self.cpu.maskN(16))
        bh = va&self.cpu.maskN(16)
        return uh+bh

    def _translate_small_page(self, pd, va):
        uh = pd&(~self.cpu.maskN(12))
        bh = va&self.cpu.maskN(12)
        return uh+bh

    def _translate_second_level(self, pd, va):
        tag = pd&3
        if tag == 1:
            return self._translate_large_page(pd, va)
        elif tag&2 != 0:
            return self._translate_small_page(pd, va)
        else:
            # Invalid
            return 0

    def _translate_first_level(self, pd, va):
        tag = pd&3
        if tag == 1:
            pte = self._translate_page_table(pd, va)
            return self._translate_second_level(pte, va)
        elif tag&2 != 0:
            return self._translate_section(pd, va)
        else:
            # Invalid
            return 0

    def translate(self, va):
        pgd = self.select_base(va)
        pmd = self._read_word(pgd + (self._level_1_table_index(va)<<2))
        pa = self._translate_first_level(pmd, va)
        return pa

# Unit test
if __name__ == "__main__":
    vm = VM("linux.reg", "linux.mem")
    print(hex(vm.select_base(0)))
    print(hex(vm.translate(0xffff0000)))
    print(hex(vm._read_word(vm.translate(0xffff0000))))
    print(hex(vm._read_word(vm.translate(0xffff0004))))
    print(hex(vm._read_word(vm.translate(0xffff0008))))
    print(hex(vm._read_word(vm.translate(0xffff000c))))
