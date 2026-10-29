"""Check which MTK ports answer the meta_tst alive frame."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODS = os.path.abspath(os.path.join(HERE, '..', 'saiyaku-athena', 'modules'))
sys.path.insert(0, MODS)
os.chdir(MODS)

import meta  # noqa: E402
from device import Device, serial_ports  # noqa: E402

print('ports:', sorted(serial_ports()))
for port in sorted(serial_ports()):
    dev = None
    try:
        dev = Device(port)
        dev.dev.timeout = 0.5
        alive = meta.is_alive(dev)
        print(port, 'ALIVE' if alive else 'no answer')
    except Exception as exc:
        print(port, 'error', exc)
    finally:
        if dev is not None:
            try:
                dev.close()
            except Exception:
                pass
