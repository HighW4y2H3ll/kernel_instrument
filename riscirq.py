#!/usr/bin/python3

import vm
import sys
import ctypes

class IRQDesp(ctypes.Structure):
    _fields_ = [
            ('link', ctypes.c_uint),
            ('r12', ctypes.c_uint),
            ('call', ctypes.c_uint),
            ]

if len(sys.argv) < 3:
    print("Usage: ./riscirq.py riscpi.reg riscpi.mem")
    sys.exit()

mm = vm.VM(sys.argv[1], sys.argv[2])
print(hex(mm.translate(0xffff0000)))
print(hex(mm.translate(0xfc012900)))    # Initial_IRQ_Code: 0x3bb12900
print(hex(mm.translate(0xfaff1fc4)))    # DefaultIRQ1VCode: 0x2015fc4
print()
print(hex(mm.translate(0xffff043c)))    # 
print(hex(mm.translate(0xfc028fe4)))    # UNDEF
# checking shared irq (27)
print(hex(mm.translate(0xfa001624+0x34)))
print(hex(mm.translate(0xfc009ea0)))
print(hex(mm.translate(0x2004a170)))    # {0, 0}

IRQ = 0xfc012c34    # virtual address
Devices = 0x201600c # physical address
for i in range(256):
    desp = IRQDesp.from_buffer_copy(mm._read(Devices+12*i, 12))
    if desp.link != 0 or desp.call != IRQ:
        print(f"{i}:")
        print(f"  {hex(desp.link)}")
        print(f"  {hex(desp.r12)}")
        print(f"  {hex(desp.call)}")
        print(f"  {hex(mm.translate(desp.call))}")
        if desp.link&1 != 0:    # Check IRQDesp_Link_Unshared
            link = IRQDesp.from_buffer_copy(mm._read(mm.translate(desp.link^1), 12))
            print(f"    {hex(link.link)}")
            print(f"    {hex(link.call)}")
