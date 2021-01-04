#!/usr/local/bin/python3

import sys
import ctypes

# Note Mount Partition: fuse have no ufs write support, install FreeBSD, and copy instrumented kernel back to the UFS partition
# > mdconfig -a -t vnode -f ./partition
# > mount /dev/md0 /mnt
# > cp newkernel /mnt/boot/kernel/kernel
# > umount /mnt
# > mdconfig -d -u md0

# Ref: https://web.archive.org/web/20131224093236/http://www.freebsd.org/cgi/man.cgi?query=disklabel&apropos=0&sektion=5&manpath=4.4BSD+Lite2&format=html
class Partition (ctypes.Structure):
    _fields_ = [
            ('p_size', ctypes.c_uint),
            ('p_offset', ctypes.c_uint),
            ('p_fsize', ctypes.c_uint),
            ('p_fstype', ctypes.c_byte),
            ('p_frag', ctypes.c_byte),
            ('p_cpg', ctypes.c_ushort),
            ]

class DiskLabel (ctypes.Structure):
    _fields_ = [
            ('d_magic', ctypes.c_uint),
            ('d_type', ctypes.c_ushort),
            ('d_subtype', ctypes.c_ushort),
            ('d_typename', ctypes.c_char * 16),
            #('d_packname', ctypes.c_char * 16),
            ('un_d_packname', ctypes.c_char * 16),

            ('d_secsize', ctypes.c_uint),
            ('d_nsectors', ctypes.c_uint),
            ('d_ntracks', ctypes.c_uint),
            ('d_ncylinders', ctypes.c_uint),
            ('d_secpercyl', ctypes.c_uint),
            ('d_secperunit', ctypes.c_uint),

            ('d_sparespertrack', ctypes.c_ushort),
            ('d_sparespercyl', ctypes.c_ushort),

            ('d_acylinders', ctypes.c_uint),

            ('d_rpm', ctypes.c_ushort),
            ('d_interleave', ctypes.c_ushort),
            ('d_trackskew', ctypes.c_ushort),
            ('d_cylskew', ctypes.c_ushort),
            ('d_headswitch', ctypes.c_uint),
            ('d_trkseek', ctypes.c_uint),
            ('d_flags', ctypes.c_uint),
            ('d_drivedata', ctypes.c_uint * 5),
            ('d_spare', ctypes.c_uint * 5),
            ('d_magic2', ctypes.c_uint),
            ('d_checksum', ctypes.c_ushort),

            ('d_npartitions', ctypes.c_ushort),
            ('d_bbsize', ctypes.c_uint),
            ('d_sbsize', ctypes.c_uint),
            ('d_partitions', Partition * 8),    # could be more
            ]

def extract_partition():
    disklabel = DiskLabel()
    with open(sys.argv[2], 'rb') as fd:
        fd.seek(0x200)  # skip first 0x200 (MBR header)
        fd.readinto(disklabel)
        #for f in disklabel._fields_:
        #    print(f[0], getattr(disklabel, f[0]))
        #for part in disklabel.d_partitions:
        #    for f in part._fields_:
        #        print(f[0], getattr(part, f[0]))
        part_offset = disklabel.d_partitions[0].p_offset * disklabel.d_secsize
        if len(sys.argv) > 3:
            fd.seek(part_offset)
            with open(sys.argv[3], 'wb') as fout:
                fout.write(fd.read())

def gen_partition():
    disklabel = DiskLabel()
    with open(sys.argv[3], 'rb') as fd:
        partdata = fd.read()
    with open(sys.argv[2], 'rb') as fd:
        fd.seek(0x200)
        fd.readinto(disklabel)
        part_offset = disklabel.d_partitions[0].p_offset * disklabel.d_secsize
        fd.seek(0)
        header = fd.read(part_offset)
    with open(sys.argv[2]+"_new", 'wb') as fd:
        fd.write(header + partdata)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./fckbsd.py x/g disklabel partition")
        sys.exit()
    if sys.argv[1] == 'x':
        extract_partition()
    elif sys.argv[1] == 'g':
        gen_partition()
    else:
        sys.exit()
