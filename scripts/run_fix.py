"""Run the adb_keys fix payload and save its output."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_robust as RR  # noqa: E402
import run_payload as RP  # noqa: E402

PATH = os.path.join(HERE, 'stage2_fix_adb.elf')


def main():
    print('watching for preloader...', flush=True)
    if not RR.catch_preloader():
        print('no preloader', flush=True)
        return
    dev = RP.M.wait_meta()
    print('meta_tst on', dev.port, flush=True)
    RP.send_chain_with(dev, PATH)
    raw = RP.M.drain(dev, 45)
    with open(os.path.join(HERE, 'fix_out.bin'), 'wb') as fout:
        fout.write(raw)
    print('--- output ---', flush=True)
    print(RP.M.safe(raw[:600]), flush=True)
    try:
        dev.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()
