#!/usr/bin/python3

import sys
import yaml
import struct

class ArchCpu(object):
    def maskN(self, n):
        return (1<<n)-1
    def translate(self, va, vm):
        raise
    def walk(self, vm):
        raise
    def page_mask(self, va, vm):
        raise

class MipsCpu(ArchCpu):
    def __init__(self, reg, mem_base=0):
        self._physical_mem_base = mem_base
        self._kseg0 = 0x80000000
        self._kseg1 = 0xa0000000
        self._kseg2 = 0xc0000000

    def translate(self, va, vm):
        if (va >= self._kseg0) and (va < self._kseg2):
            return va - self._kseg0
        # otherwise, need to emulate tlbr excp
        from mips_tlbemu import translate
        return translate(vm._mem, va)

    def walk(self, vm):
        from mips_tlbemu import translate
        vma = set()
        for va in range(0x80000000, 0x90000000, 0x1000):
            vma.add((va, va-self._kseg0, 0x1000, None))
        for va in range(0xc0000000, 0xc1000000, 0x1000):
            pa = translate(vm._mem, va)
            if pa != 0:
                vma.add((va, pa, 0x1000, None))
        return vma

# Ref: https://developer.arm.com/documentation/ddi0406/cb/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors
# Short-format support only
class ArmCpu(ArchCpu):
    def __init__(self, reg, mem_base=0):
        self._physical_mem_base = mem_base
        if reg.endswith(".yaml"):
            with open(reg, 'r') as fd:
                #regs = yaml.load(fd, Loader=yaml.FullLoader)
                regs = yaml.safe_load(fd)
            for i in range(4):
                self.ttbr0 = regs['cp15.ttbr0_el'][i]
                self.ttbr1 = regs['cp15.ttbr1_el'][i]
                if self.ttbr0 != 0 and self.ttbr1 != 0:
                    break
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

    def select_base(self, va):
        if self.N == 0:
            return self.mask_ttbr0()
        # else N > 0
        if (va & (self.maskN(self.N)<<(32-self.N))) == 0:
            return self.mask_ttbr0()
        else:
            return self.mask_ttbr1()

    def _level_1_table_index(self, va):
        return (va>>20)&self.maskN(12)

    def _level_2_table_index(self, va):
        return (va>>12)&self.maskN(8)

    def _translate_supersection_ext(self, pd):
        return (((pd>>5)&0xf)<<4)|((pd>>20)&0xf)

    def _translate_supersection(self, pd, va):
        uh = pd&(~self.maskN(24))
        ext = (self._translate_supersection_ext(pd)<<32)
        bh = va&self.maskN(24)
        return ext + uh + bh

    def _translate_section(self, pd, va):
        uh = pd&(~self.maskN(20))
        bh = va&self.maskN(20)
        return uh + bh

    def __translate_sections(self, pd, va):
        tag = pd&(1<<18)
        if tag == 0:
            return self._translate_section(pd, va)
        else:
            return self._translate_supersection(pd, va)

    def _translate_page_table(self, pd, va, vm):
        pmd = pd&(~self.maskN(10))
        pmd += (self._level_2_table_index(va)<<2)
        return vm._read_word(pmd)

    def _translate_large_page(self, pd, va):
        uh = pd&(~self.maskN(16))
        bh = va&self.maskN(16)
        return uh+bh

    def _translate_small_page(self, pd, va):
        uh = pd&(~self.maskN(12))
        bh = va&self.maskN(12)
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

    def _translate_first_level(self, pd, va, vm):
        tag = pd&3
        if tag == 1:
            pte = self._translate_page_table(pd, va, vm)
            return self._translate_second_level(pte, va)
        elif tag&2 != 0:
            return self.__translate_sections(pd, va)
        else:
            # Invalid
            return 0

    def translate(self, va, vm):
        pgd = self.select_base(va)
        pmd = vm._read_word(pgd + (self._level_1_table_index(va)<<2))
        pa = self._translate_first_level(pmd, va, vm)
        return pa

    def _parse_large_page_pte(self, vaddr, pte):
        # Note: large page 2nd layer table index have 4 bits overlap with page index,
        # (just in case) might have duplications
        pgsz = 1<<16
        pa = pte&(~self.maskN(16))
        prot = Permission(self, \
                NX = (pte>>15)&1, \
                AP2 = (pte>>9)&1, \
                AP10 = (pte>>4)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _parse_small_page_pte(self, vaddr, pte):
        pgsz = 1<<12
        pa = pte&(~self.maskN(12))
        prot = Permission(self, \
                NX = pte&1, \
                AP2 = (pte>>9)&1, \
                AP10 = (pte>>4)&3, \
                TEX = (pte>>6)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _walk_second_level(self, pmd, vbase, vm):
        pte = set()
        for ti in range(1<<8):
            e = vm._read_word(pmd | (ti<<2))
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
        pa = pte&(~self.maskN(20))
        prot = Permission(self, \
                NX = (pte>>4)&1, \
                AP2 = (pte>>15)&1, \
                AP10 = (pte>>10)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        return (vaddr, pa, pgsz, prot)

    def _walk_supersection(self, pte, vaddr):
        pgsz = 1<<24
        pa = (self._translate_supersection_ext(pte)<<32)|(pte&(~self.maskN(24)))
        prot = Permission(self, \
                NX = (pte>>4)&1, \
                AP2 = (pte>>15)&1, \
                AP10 = (pte>>10)&3, \
                TEX = (pte>>12)&7, \
                C = (pte>>3)&1, \
                B = (pte>>2)&1)
        # Note: supersection has 4 bits overlap of table index and supersection index
        return (vaddr&(~self.maskN(24)), pa, pgsz, prot)

    def _walk_first_level(self, pgd, vm):
        vma = set()
        for ti in range(1<<(12-self.N)):
            vbase = ti<<20
            e = vm._read_word(pgd | (ti<<2))
            tag = e&3
            if tag == 1:
                pmd = e&(~self.maskN(10))
                vma.update(self._walk_second_level(pmd, vbase, vm))
            elif tag&2 != 0:
                if e&(1<<18) == 0:
                    vma.add(self._walk_section(e, vbase))
                else:   # e:18 == 1
                    vma.add(self._walk_supersection(e, vbase))
            else:   # Invalid
                continue
        return vma

    def _walk_ttbr0(self, vm):
        mask = self.maskN(32-self.N)
        pgd = self.mask_ttbr0()
        return self._walk_first_level(pgd, vm)

    def _walk_ttbr1(self, vm):
        pgd = self.mask_ttbr1()
        # temporarily set N=0 when walking ttbr1
        oldN = self.N
        self.N = 0
        vma = self._walk_first_level(pgd, vm)
        self.N = oldN
        return vma

    def walk(self, vm):
        vma = set() # vma tuple: (vaddr, paddr, len, prot)
        vma.update(self._walk_ttbr0(vm))
        if self.N != 0:
            vma.update(self._walk_ttbr1(vm))
        return vma

    def page_mask(self, va, vm):
        pgd = self.select_base(va)
        pmd = vm._read_word(pgd + (self._level_1_table_index(va)<<2))
        if pmd&3 == 1:
            pte = self._translate_page_table(pmd, va, vm)
            if pte&3 == 1:
                return self.maskN(16)   # large page
            elif pte&2 != 0:
                return self.maskN(12)   # small page
            else:
                # Invalid
                return 0
        elif pmd&2 != 0:     # section
            if pmd&(1<<18) == 0:
                return self.maskN(20)   # section
            else:
                return self.maskN(24)   # supersection
        else:
            # Invalid
            return 0

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


class VM(ArchCpu):
    def __init__(self, reg, mem, mem_base=0, arch='armv7'):
        self._fd_mem = open(mem, 'rb')
        if arch == 'armv7':
            self.cpu = ArmCpu(reg,mem_base)
        elif arch == 'mipsel32':
            self.cpu = MipsCpu(reg,mem_base)
            self._mem = self._fd_mem.read()
        else:
            self.cpu = None
        assert (self.cpu)

    def __del__(self):
        self._fd_mem.close()

    def _read(self, off, sz):
        off -= self.cpu._physical_mem_base
        self._fd_mem.seek(off)
        return self._fd_mem.read(sz)

    def _read_word(self, off):
        x = self._read(off, 4)
        return struct.unpack('<I', x)[0]

    def translate(self, va):
        return self.cpu.translate(va, self)

    def walk(self):
        return self.cpu.walk(self)

    def page_mask(self, va):
        return self.cpu.page_mask(va, self)

# Unit test
if __name__ == "__main__":
    #vm = VM("linux.reg", "linux.mem")
    vm = VM(sys.argv[1], sys.argv[2], int(sys.argv[3],16) if len(sys.argv)>3 else 0)
    print(hex(vm.cpu.select_base(0)))
    #print(hex(vm.translate(0x20018)))
    print(hex(vm.translate(0x91002364)))
    print(hex(vm.translate(0xffff0000)))
    print(hex(vm._read_word(vm.translate(0xffff0000))))
    #print(hex(vm._read_word(vm.translate(0x80101960))))
    for e in vm.walk():
        print(hex(e[0]), hex(e[1]), hex(e[2]), e[3].check_read_pl1() and not e[3].check_read_pl0(), e[3].check_write_pl1(), e[3].check_exec())
