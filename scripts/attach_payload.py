"""Attach to an existing meta_tst port and send a payload."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_payload as R  # noqa: E402
from device import Device  # noqa: E402
import meta  # noqa: E402

PORT = sys.argv[2] if len(sys.argv) > 2 else 'COM9'
PATH = os.path.join(HERE, sys.argv[1])

dev = Device(PORT)
dev.dev.timeout = 0.5
if not meta.is_alive(dev):
    print('meta_tst not alive on', PORT, flush=True)
    raise SystemExit(1)
print('alive on', PORT, flush=True)
R.send_chain_with(dev, PATH)
raw = R.M.drain(dev, 12)
with open(os.path.join(HERE, 'payload_out.bin'), 'wb') as fout:
    fout.write(raw)
print('--- payload output ({}) ---'.format(len(raw)), flush=True)
print(R.M.safe(raw), flush=True)
try:
    dev.close()
except Exception:
    pass
