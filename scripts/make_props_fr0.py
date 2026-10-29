"""Build the patched persistent_properties with factoryreset=0."""

import struct

SRC = 'analysis/persistent_properties_block_519807.bin'


def read_varint(buf, i):
    out = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        out |= (b & 0x7F) << shift
        if not (b & 0x80):
            return out, i
        shift += 7


def enc_varint(v):
    out = b''
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def parse(buf):
    i = 0
    entries = []
    while i < len(buf):
        tag, i = read_varint(buf, i)
        if tag == 0:
            break
        field, wire = tag >> 3, tag & 7
        if wire != 2:
            break
        ln, i = read_varint(buf, i)
        payload = buf[i:i + ln]
        i += ln
        if field != 1:
            continue
        name = value = None
        j = 0
        while j < len(payload):
            t, j = read_varint(payload, j)
            f2, w2 = t >> 3, t & 7
            if w2 != 2:
                break
            l2, j = read_varint(payload, j)
            data = payload[j:j + l2]
            j += l2
            if f2 == 1:
                name = data
            elif f2 == 2:
                value = data
        entries.append((name, value))
    return entries


def serialize(entries):
    out = b''
    for name, value in entries:
        prop = b'\x0a' + enc_varint(len(name)) + name
        if value is not None:
            prop += b'\x12' + enc_varint(len(value)) + value
        out += b'\x0a' + enc_varint(len(prop)) + prop
    return out


raw = open(SRC, 'rb').read()
# content = up to the last non-zero
content_len = len(raw.rstrip(b'\x00'))
content = raw[:content_len]
entries = parse(content)
print('parsed', len(entries), 'entries')
print('roundtrip ok:', serialize(entries) == content)

new = []
for name, value in entries:
    n = name.decode('latin1')
    if n == 'persist.sys.factoryreset':
        print('patching', n, value, '->', b'0')
        new.append((name, b'0'))
    else:
        new.append((name, value))

out = serialize(new)
print('new content len', len(out))
blk = out + b'\x00' * (4096 - len(out))
open('analysis/props_fr0_block_519807.bin', 'wb').write(blk)

ino = bytearray(open('analysis/patched_inode_57459.bin', 'rb').read())
struct.pack_into('<I', ino, 0x04, len(out))
open('analysis/props_fr0_inode_57459.bin', 'wb').write(bytes(ino))
print('wrote props_fr0_block_519807.bin and props_fr0_inode_57459.bin')
