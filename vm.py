#!/usr/bin/python3

import sys
import yaml
import struct

class ArchCpu(object):
    def load_reg(self, reg):
        raise
    def maskN(self, n):
        return (1<<n)-1

class ArmCpu(ArchCpu):
    def __init__(self, reg, mem_base=0):
        self._physical_mem_base = mem_base
        if reg.endswith(".yaml"):
            with open(reg, 'r') as fd:
                #regs = yaml.load(fd, Loader=yaml.FullLoader)
                regs = yaml.safe_load(fd)
            self.ttbr0 = regs['cp15.ttbr0_el'][3]
            self.ttbr1 = regs['cp15.ttbr1_el'][3]
            #self.sctlr = regs['cp15.sctlr_el'][3]
            self.sctlr = 0
            self.ttbcr = 0
            self.prrr = 0
            self.nmrr = 0
        else:
            regs = {}
            for line in open(reg, 'r'):
                k, _, v = line.strip().split()
                regs[k] = int(v, 0)
            self.ttbr0 = regs['translation_table_base_0_0']
            self.ttbr1 = regs['translation_table_base_1_0']
            self.ttbcr = regs['translation_table_base_control_0']
            self.sctlr = regs['control_0']
            self.prrr  = regs['primary_region_remap_register_0']
            self.nmrr  = regs['normal_memory_remap_register_0']

        # Auxiliary
        self.N = self.ttbcr&7
        self.AFE = (self.sctlr>>29)&1
        self.TRE = (self.sctlr>>28)&1

    def mask_ttbr0(self):
        return (self.ttbr0 & (~self.maskN(14-self.N)))

    def mask_ttbr1(self):
        return (self.ttbr1 & (~self.maskN(14)))

class Permission(object):
    def __init__(self, cpu, NX, AP2, AP10, TEX, C, B):
        self.cpu = cpu
        self.NX = NX
        self.AP2 = AP2
        self.AP10 = AP10
        self.TEX = TEX
        self.C = C
        self.B = B

    def check_exec(self):
        return self.NX == 0

    # Ref: https://developer.arm.com/documentation/ddi0406/cb/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Memory-access-control/Access-permissions?lang=en
    def check_read_pl1(self):
        if self.cpu.AFE == 1:
            return True
        else:   # AFE == 0
            return self.AP10 != 0

    def check_read_pl0(self):
        if self.cpu.AFE == 1:
            return self.AP10&2 != 0
        else:   # AFE == 0
            return self.AP10 != 0 and self.AP10 != 1

    def check_read(self):
        return self.check_read_pl0() or self.check_read_pl1()

    def check_write_pl1(self):
        if self.cpu.AFE == 1:
            return self.AP2 == 0
        else:   # AFE == 0
            return self.AP2 == 0 and self.AP10 != 0

    def check_write_pl0(self):
        if self.cpu.AFE == 1:
            return self.AP2 == 0 and self.AP10&2 != 0
        else:   # AFE == 0
            return self.AP2 == 0 and self.AP10 == 3

    def check_write(self):
        return self.check_write_pl0() or self.check_write_pl1()

    # Ref: https://developer.arm.com/documentation/ddi0406/cb/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Memory-region-attributes/Short-descriptor-format-memory-region-attributes--without-TEX-remap?lang=en
    def check_mmio(self):
        if self.cpu.TRE == 0:
            pass
        else:   # TRE=1
            pass

# Ref: https://developer.arm.com/documentation/ddi0406/cb/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors
# Short-format support only
class VM(ArchCpu):
    def __init__(self, reg, mem, mem_base=0):
        self._fd_mem = open(mem, 'rb')
        self.cpu = ArmCpu(reg,mem_base)

    def __del__(self):
        self._fd_mem.close()

    def select_base(self, va):
        if self.cpu.N == 0:
            return self.cpu.mask_ttbr0()
        # else N > 0
        if (va & (self.cpu.maskN(self.cpu.N)<<(32-self.cpu.N))) == 0:
            return self.cpu.mask_ttbr0()
        else:
            return self.cpu.mask_ttbr1()

    def _read(self, off, sz):
        off -= self.cpu._physical_mem_base
        self._fd_mem.seek(off)
        return self._fd_mem.read(sz)

    def _read_word(self, off):
        x = self._read(off, 4)
        return struct.unpack('<I', x)[0]

    def _level_1_table_index(self, va):
        return (va>>20)&self.cpu.maskN(12-self.cpu.N)

    def _level_2_table_index(self, va):
        return (va>>12)&self.cpu.maskN(8)

    def _translate_supersection_ext(self, pd):
        return (((pd>>5)&0xf)<<4)|((pd>>20)&0xf)

    def _translate_supersection(self, pd, va):
        uh = pd&(~self.cpu.maskN(24))
        ext = (self._translate_supersection_ext(pd)<<32)
        bh = va&self.cpu.maskN(24)
        return ext + uh + bh

    def _translate_section(self, pd, va):
        uh = pd&(~self.cpu.maskN(20))
        bh = va&self.cpu.maskN(20)
        return uh + bh

    def __translate_sections(self, pd, va):
        tag = pd&(1<<18)
        if tag == 0:
            return self._translate_section(pd, va)
        else:
            return self._translate_supersection(pd, va)

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
            return self.__translate_sections(pd, va)
        else:
            # Invalid
            return 0

    def translate(self, va):
        pgd = self.select_base(va)
        pmd = self._read_word(pgd + (self._level_1_table_index(va)<<2))
        pa = self._translate_first_level(pmd, va)
        return pa

    def _parse_large_page_pte(self, vaddr, pte):
        # Note: large page 2nd layer table index have 4 bits overlap with page index,
        # (just in case) might have duplications
        pgsz = 1<<16
        pa = pte&(~self.cpu.maskN(16))
        prot = Permission(self.cpu, \
                NX = (pte>>15)&1, \
                AP2 = (pte>>9)&1, \
                AP10 = (pte>>4)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _parse_small_page_pte(self, vaddr, pte):
        pgsz = 1<<12
        pa = pte&(~self.cpu.maskN(12))
        prot = Permission(self.cpu, \
                NX = pte&1, \
                AP2 = (pte>>9)&1, \
                AP10 = (pte>>4)&3, \
                TEX = (pte>>6)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _walk_second_level(self, pmd, vbase):
        pte = set()
        for ti in range(1<<8):
            e = self._read_word(pmd | (ti<<2))
            tag = e&3
            if tag == 1:
                pte.add(
                        self._parse_large_page_pte(
                            vbase + ((ti&0xf0)<<12), e))
            elif tag&2 != 0:
                pte.add(
                        self._parse_small_page_pte(
                            vbase + (ti<<12), e))
            else:   # Invalid
                continue
        return pte

    def _walk_section(self, pte, vaddr):
        pgsz = 1<<20
        pa = pte&(~self.cpu.maskN(20))
        prot = Permission(self.cpu, \
                NX = (pte>>4)&1, \
                AP2 = (pte>>15)&1, \
                AP10 = (pte>>10)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _walk_supersection(self, pte, vaddr):
        pgsz = 1<<24
        pa = (self._translate_supersection_ext(pte)<<32)|(pte&(~self.cpu.maskN(24)))
        prot = Permission(self.cpu, \
                NX = (pte>>4)&1, \
                AP2 = (pte>>15)&1, \
                AP10 = (pte>>10)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        # Note: supersection has 4 bits overlap of table index and supersection index
        return (vaddr&(~self.cpu.maskN(24)), pa, pgsz, prot)

    def _walk_first_level(self, pgd):
        vma = set()
        for ti in range(1<<(12-self.cpu.N)):
            vbase = ti<<20
            e = self._read_word(pgd | (ti<<2))
            tag = e&3
            if tag == 1:
                pmd = e&(~self.cpu.maskN(10))
                vma.update(self._walk_second_level(pmd, vbase))
            elif tag&2 != 0:
                if e&(1<<18) == 0:
                    vma.add(self._walk_section(e, vbase))
                else:   # e:18 == 1
                    vma.add(self._walk_supersection(e, vbase))
            else:   # Invalid
                continue
        return vma

    def _walk_ttbr0(self):
        mask = self.cpu.maskN(32-self.cpu.N)
        pgd = self.cpu.mask_ttbr0()
        return self._walk_first_level(pgd)

    def _walk_ttbr1(self):
        pgd = self.cpu.mask_ttbr1()
        # temporarily set N=0 when walking ttbr1
        oldN = self.cpu.N
        self.cpu.N = 0
        vma = self._walk_first_level(pgd)
        self.cpu.N = oldN
        return vma

    def walk(self):
        vma = set() # vma tuple: (vaddr, paddr, len, prot)
        vma.update(self._walk_ttbr0())
        if self.cpu.N != 0:
            vma.update(self._walk_ttbr1())
        return vma

    def page_mask(self, va):
        pgd = self.select_base(va)
        pmd = self._read_word(pgd + (self._level_1_table_index(va)<<2))
        if pmd&3 == 1:
            pte = self._translate_page_table(pmd, va)
            if pte&3 == 1:
                return self.cpu.maskN(16)   # large page
            elif pte&2 != 0:
                return self.cpu.maskN(12)   # small page
            else:
                # Invalid
                return 0
        elif pmd&2 != 0:     # section
            if pmd&(1<<18) == 0:
                return self.cpu.maskN(20)   # section
            else:
                return self.cpu.maskN(24)   # supersection
        else:
            # Invalid
            return 0

# Unit test
if __name__ == "__main__":
    #vm = VM("linux.reg", "linux.mem")
    vm = VM(sys.argv[1], sys.argv[2])
    print(hex(vm.select_base(0)))
    print(hex(vm.translate(0xffff0000)))
    print(hex(vm._read_word(vm.translate(0xffff0000))))
    #print(hex(vm._read_word(vm.translate(0x80101960))))
    for e in vm.walk():
        print(hex(e[0]), hex(e[1]), hex(e[2]), e[3].check_read_pl1() and not e[3].check_read_pl0(), e[3].check_write_pl1(), e[3].check_exec())
