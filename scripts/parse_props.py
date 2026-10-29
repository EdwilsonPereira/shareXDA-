"""Parse persistent_properties protobuf (nested Property messages)."""

import struct

BLK = open('analysis/persistent_properties_block_519807.bin', 'rb').read()


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


def parse_msg(buf, start, end, depth=0, out=None):
    if out is None:
        out = []
    i = start
    while i < end:
        tag, i = read_varint(buf, i)
        if tag == 0:
            break
        field = tag >> 3
        wire = tag & 7
        if wire == 2:
            ln, i = read_varint(buf, i)
            payload = buf[i:i + ln]
            i += ln
            out.append((depth, field, payload))
            # try to descend (nested message) if it looks like one
            if payload and payload[0] == 0x0A:
                parse_msg(buf, i - ln, i, depth + 1, out)
        elif wire == 0:
            _, i = read_varint(buf, i)
        else:
            break
    return out


triples = parse_msg(BLK, 0, len(BLK))
# Reconstruct Property entries: depth0 field1 = Property message
entries = []
cur = None
for depth, field, payload in triples:
    if depth == 0 and field == 1:
        cur = {'name': None, 'value': None}
        entries.append(cur)
    elif depth == 1 and field == 1 and cur is not None:
        cur['name'] = payload.decode('latin1', 'replace')
    elif depth == 1 and field == 2 and cur is not None:
        cur['value'] = payload.decode('latin1', 'replace')

print('entries:', len(entries))
for e in entries:
    print('  %-42s = %r' % (e['name'], e['value']))
