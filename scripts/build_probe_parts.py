"""Probe which block devices / mount points are accessible from the META payload."""

import struct

from keystone import keystone as K

BASE = 0x400000
ENTRY = BASE + 0x100

PATHS = [
    '/dev/block/platform/bootdevice/by-name/lk',
    '/dev/block/platform/bootdevice/by-name/misc',
    '/dev/block/platform/bootdevice/by-name/recovery',
    '/dev/block/platform/bootdevice/by-name/boot',
    '/dev/block/platform/bootdevice/by-name/userdata',
    '/data',
    '/data/local/tmp',
    '/cache',
]

LABELS = {'hdr': '\n=== PROBE ===\n', 'ok': ' OK\n', 'fail': ' FAIL\n',
          'err': ' ERR\n', 'end': '=== PROBE_END ===\n'}
ORDER = list(LABELS)

BLOB = b''
OFF = {}
for _k in ORDER:
    OFF[_k] = len(BLOB)
    BLOB += LABELS[_k].encode() + b'\x00'
PATH_OFF = {}
for _pth in PATHS:
    PATH_OFF[_pth] = len(BLOB)
    BLOB += _pth.encode() + b'\x00'
while len(BLOB) % 4:
    BLOB += b'\x00'
TABLE_OFF = len(BLOB)


def movconst(reg, v):
    return '    movw {0}, #{1:#06x}\n    movt {0}, #{2:#06x}'.format(
        reg, v & 0xFFFF, (v >> 16) & 0xFFFF)


def make(addr_of, table_addr):
    def C(reg, n):
        return movconst(reg, addr_of(n))

    return """
_start:
    push {{r4, r5, r6, lr}}
{hdr}
    bl  puts
{tab}
    mov r4, r0
loop:
    ldr r5, [r4]
    cmp r5, #0
    beq done
    mov r0, r5
    bl  puts
    mov r0, r5
    mov r1, #0
    mov r7, #5
    svc #0
    cmp r0, #0
    blt fail
    mov r6, r0
    mov r0, r6
    mov r7, #6
    svc #0
{ok}
    bl  puts
    b   next
fail:
{err}
    bl  puts
next:
    add r4, r4, #4
    b   loop
done:
{end}
    bl  puts
    mov r0, #0
    mov r7, #1
    svc #0
puts:
    mov r1, r0
    mov r2, #0
pl:
    ldrb r3, [r1, r2]
    cmp r3, #0
    beq pd
    add r2, r2, #1
    b   pl
pd:
    mov r0, #1
    mov r7, #4
    svc #0
    bx  lr
""".format(
        hdr=C('r0', 'hdr'), ok=C('r0', 'ok'), err=C('r0', 'err'),
        end=C('r0', 'end'), tab=movconst('r0', table_addr),
    )


def build():
    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_ARM)
    code1, _ = ks.asm(make(lambda n: BASE, BASE), ENTRY)
    clen = len(bytes(code1))
    data_at = ENTRY + clen
    table_at = data_at + TABLE_OFF
    # build table bytes using the soon-to-be address (pass 2)
    table = b''.join(struct.pack('<I', data_at + PATH_OFF[p]) for p in PATHS)
    table += b'\x00\x00\x00\x00'
    blob_data = BLOB + table
    code2, count = ks.asm(make(lambda n: data_at + OFF[n], table_at), ENTRY)
    code2 = bytes(code2)
    assert len(code2) == clen, (len(code2), clen)
    blob = b'\x00' * (ENTRY - BASE - 84) + code2 + blob_data
    while len(blob) % 4:
        blob += b'\x00'
    filesz = 84 + len(blob)
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    ehdr = ident + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, ENTRY, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    phdr = struct.pack('<IIIIIIII', 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
    out = 'analysis/stage2_probe_parts.elf'
    open(out, 'wb').write(ehdr + phdr + blob)
    print('wrote', out, filesz, 'bytes, table_at', hex(table_at))


if __name__ == '__main__':
    build()
