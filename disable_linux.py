#!/usr/bin/python3

import vm
import os
import re
import sys
os.environ['LIBCAPSTONE_PATH'] = os.path.join(os.path.dirname(__file__), "capstone")

import keystone.bindings.python.keystone as keystone
import capstone.bindings.python.capstone as capstone


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


if len(sys.argv) < 4:
    print("Usage: ./riscirq.py regfile memfile kernel")
    sys.exit()

uart = 0x805953f4
fbdma = 0x8054a274
usb1 = 0x806325ec
usb2 = 0x80640800
usb3 = 0x8061d9f4
mm = vm.VM(sys.argv[1], sys.argv[2])
with open(sys.argv[3], 'rb') as fd:
    kernel_data = fd.read()
cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM|capstone.CS_MODE_LITTLE_ENDIAN)
ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM|keystone.KS_MODE_LITTLE_ENDIAN)

dis = [uart]
dis = [fbdma]
dis = [usb1, usb2, usb3]

patchset = {}
for bp in dis:
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
    patchset[kern_off] = patching(kernel_data, kern_off, "mov r0, #2; mov pc, lr;")
    #patchset[kern_off+4] = patching(kernel_data, kern_off+4, "b $.;")


if len(sys.argv) > 4:
    with open(sys.argv[4], 'wb') as fd:
        data = kernel_data
        for off, patch in patchset.items():
            data = data[:off] + bytes(patch[0]) + data[off+len(patch[0]):]
        fd.write(data)

