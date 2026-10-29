"""Generic block reader for the userdata partition.

Usage: py analysis\\build_blk.py <base_block> <count> [tag]
Reads `count` 4KB blocks starting at `base_block`, streams them raw over serial.
"""

import struct
import sys

from keystone import keystone as K

BASE = 0x400000
ENTRY = BASE + 0x100
BS = 4096


def movconst(reg, value):
    return '    movw {0}, #{1:#06x}\n    movt {0}, #{2:#06x}'.format(
        reg, value & 0xFFFF, (value >> 16) & 0xFFFF
    )


def make_source(addr_of, base_block, total):
    def C(reg, name):
        return movconst(reg, addr_of(name))

    off64 = base_block * BS
    off_hi32 = (off64 >> 32) & 0xFFFFFFFF
    off_lo32 = off64 & 0xFFFFFFFF

    return """
_start:
    push {{r4, r5, r6, lr}}

{tag}
    bl  puts

    movw r0, #0x0000
    movt r0, #0x5000
    movw r1, #0x0000
    movt r1, #0x0004
    mov r2, #3
    mov r3, #0x22
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    mov r6, r0
    cmp r0, #0
    blt done

{ud}
    mov r1, #0
    bl  sys_open
    cmp r0, #0
    blt rd_fail
    mov r5, r0

    // _llseek(fd, hi32, lo32, &res, SEEK_SET)
    sub sp, sp, #16
    mov r0, r5
    movw r1, #{hi32_lo}
    movt r1, #{hi32_hi}
    movw r2, #{lo32_lo}
    movt r2, #{lo32_hi}
    mov r3, sp
    mov r4, #0
    mov r7, #140
    svc #0
    add sp, sp, #16

    mov r0, r5
    mov r1, r6
    movw r2, #{total_lo}
    movt r2, #{total_hi}
    mov r7, #3
    svc #0
    mov r4, r0

{blk_msg}
    bl  puts

    mov r0, #1
    mov r1, r6
    mov r2, r4
    mov r7, #4
    svc #0

{end_msg}
    bl  puts
    b   done

rd_fail:
    bl  err_sym

done:
    mov r0, #0
    mov r7, #1
    svc #0

sys_open:
    mov r2, #0
    mov r7, #5
    svc #0
    bx  lr

err_sym:
    push {{lr}}
    cmn r0, #13
    beq err_eacces
    cmn r0, #2
    beq err_enoent
    cmn r0, #1
    beq err_eperm
    cmn r0, #22
    beq err_einval
{eother}
    bl  puts
    pop {{pc}}
err_eacces:
{eacces}
    bl  puts
    pop {{pc}}
err_enoent:
{enoent}
    bl  puts
    pop {{pc}}
err_eperm:
{eperm}
    bl  puts
    pop {{pc}}
err_einval:
{einval}
    bl  puts
    pop {{pc}}

puts:
    mov r1, r0
    mov r2, #0
puts_loop:
    ldrb r3, [r1, r2]
    cmp r3, #0
    beq puts_done
    add r2, r2, #1
    b   puts_loop
puts_done:
    mov r0, #1
    mov r7, #4
    svc #0
    bx  lr
""".format(
        tag=C('r0', 'tag'), blk_msg=C('r0', 'blk_msg'),
        end_msg=C('r0', 'end_msg'), ud=C('r0', 'ud'),
        hi32_lo=off_hi32 & 0xFFFF, hi32_hi=(off_hi32 >> 16) & 0xFFFF,
        lo32_lo=off_lo32 & 0xFFFF, lo32_hi=(off_lo32 >> 16) & 0xFFFF,
        total_lo=total & 0xFFFF, total_hi=(total >> 16) & 0xFFFF,
        eacces=C('r0', 'eacces'), enoent=C('r0', 'enoent'),
        eperm=C('r0', 'eperm'), einval=C('r0', 'einval'),
        eother=C('r0', 'eother'),
    )


def build(base_block, count, tag):
    total = count * BS
    if total > 0x40000:
        raise SystemExit('too big for 256KB buffer')

    LABELS = {
        'tag': '\nBLK_{}\n'.format(tag),
        'blk_msg': '\n=== BLK ===\n',
        'end_msg': '\n=== BLK_END ===\n',
        'ud': '/dev/block/platform/bootdevice/by-name/userdata',
        'eacces': 'EACCES\n',
        'enoent': 'ENOENT\n',
        'eperm': 'EPERM\n',
        'einval': 'EINVAL\n',
        'eother': 'EOTHER\n',
    }
    ORDER = list(LABELS)
    DATA = b''.join(LABELS[k].encode() + b'\x00' for k in ORDER)
    OFFSET = {}
    _p = 0
    for _k in ORDER:
        OFFSET[_k] = _p
        _p += len(LABELS[_k].encode()) + 1

    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_ARM)
    code1, _ = ks.asm(make_source(lambda n: BASE, base_block, total), ENTRY)
    code_len = len(bytes(code1))
    data_at = ENTRY + code_len
    code2, count_ins = ks.asm(
        make_source(lambda n: data_at + OFFSET[n], base_block, total), ENTRY)
    code2 = bytes(code2)
    assert len(code2) == code_len, (len(code2), code_len)

    pad = ENTRY - BASE - 52 - 32
    blob = b'\x00' * pad + code2 + DATA
    filesz = 52 + 32 + len(blob)
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    ehdr = ident + struct.pack(
        '<HHIIIIIHHHHHH', 2, 40, 1, ENTRY, 52, 0, 0, 52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack('<IIIIIIII', 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
    elf = ehdr + phdr + blob
    with open('analysis/stage2_blk.elf', 'wb') as fout:
        fout.write(elf)
    print('blk {}-{} ({} blocks, {} bytes) -> elf {} bytes, insns {}'.format(
        base_block, base_block + count - 1, count, total, len(elf), count_ins))


if __name__ == '__main__':
    base_block = int(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    tag = sys.argv[3] if len(sys.argv) > 3 else str(base_block)
    build(base_block, count, tag)
