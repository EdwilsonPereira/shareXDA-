"""Parse the dumped ext4 userdata to locate /data/misc/adb/adb_keys."""

import struct

RAW = open('analysis/userdata_dump.bin', 'rb').read()
marker = b'=== USERDATA_RAW ===\n'
i = RAW.find(marker)
assert i >= 0, 'marker not found'
data = RAW[i + len(marker):i + len(marker) + 0x40000]
print('raw ext4 bytes:', len(data))


def u32(b, off):
    return struct.unpack_from('<I', b, off)[0]


def u16(b, off):
    return struct.unpack_from('<H', b, off)[0]


# superblock at 1024
sb = 1024
magic = u16(data, sb + 0x38)
print('magic {:#x} (expect 0xef53)'.format(magic))
log_bs = u32(data, sb + 0x18)
bs = 1024 << log_bs
print('block size', bs, 'log_bs', log_bs)
inodes_per_group = u32(data, sb + 0x28)
inodes_count = u32(data, sb + 0x0)
blocks_per_group = u32(data, sb + 0x20)
first_data_block = u32(data, sb + 0x14)
first_ino = u32(data, sb + 0x54)
inode_size = u16(data, sb + 0x58)
feat_incompat = u32(data, sb + 0x60)
desc_size = u16(data, sb + 0xfe)
if desc_size == 0:
    desc_size = 32 if not (feat_incompat & 0x80) else 64
print('inodes_per_group', inodes_per_group, 'inodes_count', inodes_count)
print('blocks_per_group', blocks_per_group, 'first_data_block', first_data_block)
print('inode_size', inode_size, 'desc_size', desc_size)
print('feat_incompat {:#x} 64bit={} filetype={}'.format(
    feat_incompat, bool(feat_incompat & 0x80), bool(feat_incompat & 0x2)))

# group descriptor table
gdt_block = (first_data_block + 1) if bs == 1024 else 1
gdt_off = gdt_block * bs
print('gdt block', gdt_block, 'offset', gdt_off)


def group_desc(g):
    off = gdt_off + g * desc_size
    itable_lo = u32(data, off + 0x8)
    itable_hi = u32(data, off + 0x28) if desc_size >= 64 else 0
    return (itable_hi << 32) | itable_lo


def inode_table_block(n):
    g = (n - 1) // inodes_per_group
    idx = (n - 1) % inodes_per_group
    itb = group_desc(g)
    return itb, idx, itb * bs + idx * inode_size


def read_inode(n):
    itb, idx, off = inode_table_block(n)
    return data[off:off + inode_size]


def inode_mode(inod):
    return u16(inod, 0x0)


def inode_size_lo(inod):
    return u32(inod, 0x4)


def inode_flags(inod):
    return u32(inod, 0x20)


EXTENTS_FL = 0x80000
S_IFDIR = 0x4000
S_IFREG = 0x8000


def inode_blocks(inod):
    """Return list of (logical_block, physical_block) for an inode via extents."""
    flags = inode_flags(inod)
    i_block = inod[0x28:0x28 + 60]
    if not (flags & EXTENTS_FL):
        # legacy block pointers (12 direct, 1 indirect)
        out = []
        for k in range(12):
            b = u32(inod, 0x28 + k * 4)
            if b:
                out.append((k, b))
        return out
    # extents
    eh_magic = u16(i_block, 0)
    assert eh_magic == 0xF30A, hex(eh_magic)
    depth = u16(i_block, 6)
    n_entries = u16(i_block, 2)
    out = []
    pos = 12  # ext4_extent_header size
    if depth == 0:
        for k in range(n_entries):
            ee_block = u32(i_block, pos)
            ee_len = u16(i_block, pos + 4)
            ee_start_hi = u16(i_block, pos + 6)
            ee_start_lo = u32(i_block, pos + 8)
            start = (ee_start_hi << 32) | ee_start_lo
            for j in range(ee_len):
                out.append((ee_block + j, start + j))
            pos += 12
    else:
        # depth > 0: index nodes; recursively read leaf extents
        for k in range(n_entries):
            ei_block = u32(i_block, pos)
            ei_leaf_hi = u16(i_block, pos + 4)
            ei_leaf_lo = u32(i_block, pos + 6)
            leaf = (ei_leaf_hi << 32) | ei_leaf_lo
            # read the leaf block (extent header + extents)
            leaf_off = leaf * bs
            leaf_data = data[leaf_off:leaf_off + bs]
            lh_magic = u16(leaf_data, 0)
            lh_depth = u16(leaf_data, 6)
            lh_n = u16(leaf_data, 2)
            p2 = 12
            if lh_depth == 0:
                for m in range(lh_n):
                    blk = u32(leaf_data, p2)
                    ln = u16(leaf_data, p2 + 4)
                    shi = u16(leaf_data, p2 + 6)
                    slo = u32(leaf_data, p2 + 8)
                    st = (shi << 32) | slo
                    for j in range(ln):
                        out.append((blk + j, st + j))
                    p2 += 12
    return out


def inode_read(inod, off, size):
    """Read bytes from an inode's file content."""
    blocks = inode_blocks(inod)
    if not blocks:
        return b''
    # build a map of logical->physical
    result = b''
    end = off + size
    for lb, pb in blocks:
        if lb * bs >= end:
            break
        if (lb + 1) * bs <= off:
            continue
        src = data[pb * bs:pb * bs + bs]
        result += src
    return result[:size] if False else result


def read_file(inod, size):
    blocks = inode_blocks(inod)
    if not blocks:
        return b''
    buf = bytearray()
    for lb, pb in sorted(blocks):
        buf += data[pb * bs:pb * bs + bs]
    return bytes(buf[:size])


def list_dir(inod):
    size = inode_size_lo(inod)
    content = read_file(inod, size)
    entries = []
    off = 0
    while off < len(content):
        ino = u32(content, off)
        rec_len = u16(content, off + 4)
        name_len = u8(content, off + 6)
        file_type = u8(content, off + 7)
        name = content[off + 8:off + 8 + name_len].decode('latin1', 'replace')
        entries.append((ino, name, file_type))
        if rec_len == 0:
            break
        off += rec_len
    return entries


def u8(b, off):
    return b[off]


# walk from root (inode 2)
root = read_inode(2)
print('root mode {:#o} size {}'.format(inode_mode(root), inode_size_lo(root)))
entries = list_dir(root)
print('root entries count:', len(entries))
for ino, name, ft in entries:
    if name in ('misc', 'data', 'local', 'adb', 'system', 'vendor'):
        print('  root entry: inode={} name={!r} type={}'.format(ino, name, ft))

# find "misc"
misc_ino = None
for ino, name, ft in entries:
    if name == 'misc':
        misc_ino = ino
if misc_ino:
    misc = read_inode(misc_ino)
    misc_entries = list_dir(misc)
    print('\n/misc entries:', len(misc_entries))
    adb_ino = None
    for ino, name, ft in misc_entries:
        print('   misc: inode={} name={!r} type={}'.format(ino, name, ft))
        if name == 'adb':
            adb_ino = ino
    if adb_ino:
        adb = read_inode(adb_ino)
        adb_entries = list_dir(adb)
        print('\n/misc/adb entries:', len(adb_entries))
        for ino, name, ft in adb_entries:
            print('      adb: inode={} name={!r} type={}'.format(ino, name, ft))
            if name == 'adb_keys':
                ak = read_inode(ino)
                print('\n      adb_keys: inode={} size={} mode={:#o}'.format(
                    ino, inode_size_lo(ak), inode_mode(ak)))
                print('      blocks:', inode_blocks(ak))
                print('      content:', read_file(ak, inode_size_lo(ak))[:200])
