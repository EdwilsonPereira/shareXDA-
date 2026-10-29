# shareXDA — Echo Show 8 (athena) research notes & tools

Everything needed to reproduce the path that took a **locked PS7551/2335** Echo Show 8
(2nd gen, `athena`) to **PS75741/7082 + unlocked bootloader + TWRP + LineageOS 18.1**.

> ⚠️ **Read first.** This is invasive research on your own hardware. Writing raw blocks to
> the userdata partition can corrupt the filesystem; flashing the bootloader can brick the
> device. Keep raw backups. No warranty of any kind.

---

## What's inside

```
shareXDA/
├── README.md            <- this file
├── GUIA_FORUM.md        <- the post to share (EN + PT), narrative, no code
├── METODO_TECNICO.md    <- the actual method: ext4 surgery, inode/xattr/bitmaps, OTA trick
└── scripts/             <- the payload builders and runners used
    └── README.md        <- what each script does and how to adapt it
```

---

## The problem in one paragraph

The Saiyaku exploit has profiles for specific builds only. On **PS7551/2335** it has none,
so the root payload falls back to the newest PS75741 profile and fails. To unlock, the
device must first be on **PS75741** — and to update a locked unit, you first need **ADB**.
The scripts here are what let a `system`-privileged META payload write the userdata ext4
directly, enabling ADB without root, so the stock updater can move the device to 7082.

---

## Requirements

- Windows PC (Linux works with small path edits), **USB data cable**
- Python 3 + `pyserial` + `keystone-engine`
  ```
  py -m pip install pyserial keystone-engine
  ```
- MediaTek USB drivers (device shows as `MediaTek USB VCOM` / `PreLoader`)
- The **Saiyaku-Athena v1.1.x** package (its `modules/` are imported by these scripts)

---

## How to use the scripts

The runners import the tool's modules (`device.py`, `meta.py`, `exploit.py`, …), so they
must live **inside the tool's tree**:

```
saiyaku-athena-v1.1.1/
  analysis/          <- copy every .py from this package's scripts/ here
  saiyaku-athena/
    modules/         <- from the official package
    bin/firmware/    <- ditto
```

Then follow `METODO_TECNICO.md` step by step. The **block and inode numbers are specific to
my unit** — you must re-derive them on your device with `build_v23.py` + `parse_ext4.py`
(see `scripts/README.md`).

---

## Credits

- **Saiyaku-Athena** — R0rt1z2, bengris32, jackmthws (exploit, firmware images, TWRP)
- **LineageOS 18.1 for athena** — R0rt1z2, bengris32, FieryFlames
- The ext4 userdata approach, the OOBE bypass and the OTA-scheduler trick: this document.

## License

Scripts: do whatever you want, no warranty. Text: CC BY-SA.
