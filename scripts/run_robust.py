"""Robust runner: catch the preloader on any port (not only new ones),
send METAMETA, wait for meta_tst, then send a specific payload.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import serial  # noqa: E402

import run_payload as R  # noqa: E402
import meta  # noqa: E402
from device import Device, serial_ports  # noqa: E402

SKIP = {'COM1', 'COM8'}


def catch_preloader(timeout=900):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for port in serial_ports():
            if port in SKIP:
                continue
            s = None
            try:
                s = serial.Serial(port, 115200, timeout=0.05)
            except Exception:
                continue
            try:
                data = b''
                deadline = time.monotonic() + 1.2
                got = False
                while time.monotonic() < deadline:
                    c = s.read(16)
                    if c:
                        data += c
                        if b'Y' in data:
                            got = True
                            break
                if not got:
                    continue
                s.reset_input_buffer()
                s.write(b'METAMETA')
                s.flush()
                time.sleep(0.3)
                resp = s.read(64)
                print('[{}] METAMETA on {} resp={!r}'.format(
                    time.strftime('%H:%M:%S'), port, resp), flush=True)
                return True
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        time.sleep(0.2)
    return False


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: run_robust.py <stage2.elf>')
    path = os.path.abspath(sys.argv[1])
    if not os.path.exists(path):
        alt = os.path.join(HERE, os.path.basename(sys.argv[1]))
        if os.path.exists(alt):
            path = alt
    if not os.path.exists(path):
        raise SystemExit('missing ' + path)
    print('watching for preloader...', flush=True)
    if not catch_preloader():
        print('no preloader', flush=True)
        return
    dev = R.M.wait_meta()
    print('meta_tst on', dev.port, flush=True)
    R.send_chain_with(dev, path)
    raw = R.M.drain(dev, 12)
    with open(os.path.join(HERE, 'payload_out.bin'), 'wb') as fout:
        fout.write(raw)
    print('--- payload output ({}) ---'.format(len(raw)), flush=True)
    print(R.M.safe(raw), flush=True)
    try:
        dev.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()

