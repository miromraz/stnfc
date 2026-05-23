# stnfc

A userspace NFC toolkit for the Google Pixel 4a (codename **sunfish**)
running postmarketOS, talking directly to the **STMicroelectronics
ST21NFC** contactless front-end (the CLF inside the ST54J SiP) over
`/dev/i2c-2` + the GPIO chardev — **no kernel NFC driver required**.

Built bottom-up from raw NCI 2.0 over I2C, including the ST-proprietary
RF-enable (`PROP_NFC_MODE_SET`) the chip needs before any radio
activity, the listen-mode discovery for card emulation, and a
hand-rolled state machine for Type 4 NDEF tag emulation. The companion
kernel driver work lives in another branch and is on hold while this
userspace path is fleshed out.

## What `stnfc` does today

| Subcommand | Verified |
|-|-|
| `info / reset / nci / drain / raw HH..` | yes (debug primitives) |
| `poll` | yes — detect tag, UID, type, RF protocol |
| `read [blk cnt]` | yes — MIFARE Classic crypto1 auth + block read |
| `write blk [hex]` | yes — MIFARE Classic block write + read-back verify |
| `dump` | yes — full MIFARE Classic 1K (16 sectors × 4 blocks, 64/64) |
| `apdu HH HH ...` | yes — ISO-DEP APDU transceive (identified an NXP MIFARE DESFire EV1 4K via Get Version) |
| `ndef-read` | partial — Type 2 + Type 4 dispatch + Type 4 APDU flow proven |
| `ndef-write <text>` | shipped — Type 2 NTAG write (no NTAG handy to verify) |
| `emulate-ndef [url\|text]` | yes — Type 4 NDEF tag emulation, end-to-end with another phone |
| `emulate-apdu <conf>` | yes — programmable HCE, 24 APDUs handled across 8 reader taps |
| `clone <out>` | yes (Type 4 + MIFARE dump paths) |

## Repo layout

```
stnfc/
├── tool/                 the C userspace tool
│   ├── stnfc.c           single-file driver, NCI-over-I2C
│   └── configs/          example apdu-rule configs for emulate-apdu / clone
├── docs/
│   └── BRINGUP.md        chip-bringup writeup (NCI sequence, GPIOs, gotchas)
├── gui/                  Kirigami QML GUI for Plasma Mobile (planned)
└── packaging/
    └── alpine/           Alpine apk / pmaports packaging (planned)
```

## Hardware target

- **Chip**: STMicroelectronics ST21NFC CLF (inside the ST54J SiP)
- **Bus**: I2C, `/dev/i2c-2` (Qualcomm Geni I2C SE2), slave address `0x08`, 400 kHz
- **Reset / VEN**: SoC TLMM gpio 67 (active-high)
- **IRQ**: SoC TLMM gpio 37
- **Device**: Google Pixel 4a (sunfish), Qualcomm SM7150 / Snapdragon 730G

See `docs/BRINGUP.md` for the full chip-bringup writeup including the
NCI init sequence, the MIFARE-Classic-over-NCI byte format, the
listen-mode discovery configuration, and the things that took a while
to figure out.

## Build

The tool is a single-file static aarch64 binary. Cross-compile on a
workstation:

```
make
```

Produces `./stnfc` (~870 KB statically linked). Copy to the target
phone and run as root (it needs `/dev/i2c-2` + `/dev/gpiochip2`):

```
scp stnfc user@<phone>:/tmp/
ssh user@<phone> 'sudo /tmp/stnfc poll'
```

## What `stnfc` deliberately does NOT do

- **MIFARE Classic listen-mode emulation** — the ST CLF lacks the
  hardware mode. Emulating an arbitrary MIFARE Classic tag from this
  phone is not achievable on this hardware, no matter the software.
- **Contactless payments** — needs the eSE + Google/Play Integrity
  attestation, which a postmarketOS phone fails by construction.
- **Wake-from-suspend** — this is a userspace polling tool, not a
  kernel driver; it does not arm the IRQ for system wakeup.

For the achievable subset (tag read/write, NDEF read/write, ISO-DEP
APDU transceive, Type 4 NDEF tag emulation, programmable HCE), see the
feature table at the top of this README.
