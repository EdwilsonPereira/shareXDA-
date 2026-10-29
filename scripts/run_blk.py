"""Run stage2_blk.elf and save the raw block dump."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_robust as RR  # noqa: E402
import run_payload as RP  # noqa: E402

PATH = os.path.join(HERE, 'stage2_blk.elf')
OUT = os.path.join(HERE, 'blk_out.bin')


def main():
    print('watching for preloader...', flush=True)
    if not RR.catch_preloader():
        print('no preloader', flush=True)
        return
    dev = RP.M.wait_meta()
    print('meta_tst on', dev.port, flush=True)
    RP.send_chain_with(dev, PATH)
    raw = RP.M.drain(dev, 60)
    with open(OUT, 'wb') as fout:
        fout.write(raw)
    print('--- captured {} bytes ---'.format(len(raw)), flush=True)
    if len(raw) > 0:
        try:
            import parse_blk
            parse_blk.parse()
        except Exception as e:
            print('Parse error:', e)
    else:
        print('[!] 0 bytes recebidos neste ciclo (race condition comum no META). Basta repetir a execucao!', flush=True)
    try:
        dev.close()
    except Exception:
        pass


if __name__ == '__main__':
    main()
