"""Validate the injected artefacts and parse persistent_properties."""

import struct

BLK = open('analysis/persistent_properties_block_519807.bin', 'rb').read()
INODE = open('analysis/fixed_adb_inode_164165.bin', 'rb').read()
DIRB = open('analysis/adb_dir_block_655917.bin', 'rb').read()


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


print('=== fixed adb inode 164165 ===')
print('mode   %#o' % u16(INODE, 0x0))
print('uid    %d  gid %d' % (u16(INODE, 0x2), u16(INODE, 0x18)))
print('size   %d' % u32(INODE, 0x4))
print('links  %d' % u16(INODE, 0x1a))
print('flags  %#x' % u32(INODE, 0x20))
print('i_block0 (extent hdr) %#x' % u16(INODE, 0x28))
print('extent entries %d depth %d' % (u16(INODE, 0x2A), u16(INODE, 0x2E)))
print('ee_start_lo %d' % u32(INODE, 0x34))
print('checksum_lo %#x at 0x7c, checksum_hi %#x at 0x82'
      % (u16(INODE, 0x7C), u16(INODE, 0x82)))
print('extra_isize %#x' % u16(INODE, 0x80))

print()
print('=== adb dir block 655917 dirents ===')
off = 0
while off < len(DIRB) - 8:
    ino = u32(DIRB, off)
    rec = u16(DIRB, off + 4)
    nl = DIRB[off + 6]
    ft = DIRB[off + 7]
    if rec == 0:
        print('  rec_len 0 at', off)
        break
    name = DIRB[off + 8:off + 8 + nl]
    print('  off %4d inode %d rec %4d type %d name %r' % (off, ino, rec, ft, name))
    off += rec

print()
print('=== persistent_properties entries ===')


def parse_pb(buf):
    out = []
    i = 0
    while i < len(buf):
        tag = buf[i]
        if tag == 0:
            break
        field = tag >> 3
        wire = tag & 7
        i += 1
        if wire == 2:
            ln = buf[i]
            i += 1
            if ln > 0x7F:
                ln = ((ln & 0x7F) << 7) | buf[i]
                i += 1
            val = buf[i:i + ln]
            i += ln
            out.append((field, val))
        elif wire == 0:
            while buf[i] & 0x80:
                i += 1
            i += 1
            out.append((field, None))
        else:
            break
    return out


entries = parse_pb(BLK[:u32(BLK, 0) if False else len(BLK)])
cur = {}
for field, val in entries:
    if field == 1 and val:
        cur = {'key': val.decode('latin1', 'replace')}
    elif field == 2 and val:
        cur['val'] = val.decode('latin1', 'replace')
        out = cur
        print('  %-45s = %r' % (out.get('key'), out.get('val')))
