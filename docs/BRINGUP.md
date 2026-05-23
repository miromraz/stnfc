# Pixel 4a (sunfish) NFC bringup — research findings

Research phase, 2026-05-22. Methodology: `hardware-driver-bringup` skill.
Six parallel research agents + local verification against the kernel fork
(`sunfish-vibrator-v6.18.0`) and the pmaports overlay.

## TL;DR

- The NFC chip is **STMicroelectronics ST54J**, **not NXP**. The whole
  premise of "NXP drivers / decompile NXP blobs" was wrong — caught in
  Phase 0 recon, before any wasted disassembly.
- **GPL kernel source exists** (`drivers/nfc/st21nfc.c`, GPL-2.0).
  Decompilation is **not needed** for the kernel driver. See the
  "Decompilation" section for what little Ghidra *could* still help with.
- Realistic outcome: **NFC tag read/write** through the `neard` daemon.
  **Contactless payments are impossible** on a Linux phone (structural —
  needs the eSE + Google/bank attestation, not a software gap).

## 1. Hardware — what and where

ST54J is a System-in-Package: an **ST21NFC contactless front-end (CLF)**
die + an **ST54J embedded Secure Element** (ST33-based) in one part.
Only the CLF matters for tag read/write; the eSE is for card emulation
/ payments and is out of scope.

| Block | Bus | mainline node | SoC addr | I2C/CS | speed |
|-|-|-|-|-|-|
| ST21NFC CLF | I2C | `&i2c2` | `i2c@888000` | addr `0x08` | 400 kHz |
| ST54J eSE | SPI | `qupv3_se1_spi` | — | CS 1 | 8 MHz |

`&i2c2` in mainline == `qupv3_se2_i2c` downstream (same `i2c@888000`).
The mainline `sm7150-google-sunfish.dts` **already has placeholders**:
`&i2c2 { … /* st21nfc nfc@8 */ }` (line ~564) and
`/* st,st54j_se @ 1 */` (line ~904).

### GPIO / signal map (SM7150 TLMM)

| Signal | GPIO | Direction / role | Notes |
|-|-|-|-|
| IRQ / host-int | gpio37 | input | `interrupts = <37 0>`, pull-up, 2 mA; rising-edge default |
| reset / VEN | gpio67 | output | drive HIGH = powered/out-of-reset |
| pidle | gpio94 | input | power-idle monitor; optional, stats only |
| clkreq | gpio31 | input | CLK_REQ; `st,clk_pinctrl` set = gated ref clock, no free clock |
| eSE reset | gpio63 | output | SPI side; eSE only |

There is **no dedicated firmware-download (DWL_REQ) pin** — unlike NXP
parts. ST21NFC enters firmware-download mode via a VEN/IRQ pulse
sequence, and the CLF self-boots from mask ROM, so a basic NCI bringup
needs **no host-loaded firmware blob at all**.

## 2. Source of truth (GPL — read it, don't disassemble)

- Downstream kernel: `https://android.googlesource.com/kernel/msm/`
  branch `android-msm-sunfish-4.14-android13-qpr3`.
  GitHub mirror: `https://github.com/GrapheneOS/kernel_google_sunfish`.
- Driver: `drivers/nfc/st21nfc.c` + `st21nfc.h` — GPL-2.0,
  DRIVER_VERSION "2.0.15", ~1100 lines. A *raw-NCI char device*
  (`/dev/st21nfc`): it only shuttles NCI frames I2C↔userspace and
  controls the reset GPIO via ioctl. All NCI intelligence lives in
  Android's userspace `libnfc-nci`.
- eSE driver: `drivers/nfc/ese/st54j_se.c`.
- Downstream DTS: `arch/arm64/boot/dts/google/sm7150-sunfish-nfc.dtsi`:

```dts
&qupv3_se2_i2c {
	status = "ok";
	st21nfc: st21nfc@08 {
		compatible = "st,st21nfc";
		reg = <0x08>;
		interrupt-parent = <&tlmm>;
		interrupts = <37  0>;
		reset-gpios = <&tlmm 67 0x00>;
		irq-gpios = <&tlmm 37 0x00>;
		pidle-gpios = <&tlmm 94 0x00>;
		clkreq-gpios = <&tlmm 31 0x00>;
		st,clk_pinctrl;
		status = "ok";
	};
};
```

### Downstream power-on / reset sequence (from `st21nfc.c`)

1. Probe: get IRQ gpio (input), reset gpio (`GPIOD_OUT_HIGH` — powered
   at probe), optional pidle + clkreq gpios.
2. `misc_register` → `/dev/st21nfc`; `device_init_wakeup(true)`.
3. IRQ is **not** requested in probe — userspace arms it via the
   `ST21NFC_SET_POLARITY_*` ioctl (rising-edge or level-high).
4. Reset pulse (ioctl) — double pulse to exit Quick-boot mode:
   `reset=0; msleep(20); reset=1; usleep(10ms); reset=0; msleep(20); reset=1;`
5. NCI framing: read 3-byte header, byte[2] = payload length, then read
   payload; `0x7e` idle bytes are skipped.

## 3. Mainline gap analysis

Mainline `drivers/nfc/` (confirmed in the kernel fork) contains:
`nxp-nci/`, `st-nci/`, `st21nfca/`, `st95hf/`, `virtual_ncidev.c`, …

- **No `st21nfc.c`, no ST54J driver upstream.**
- `st-nci/` — ST ST21NFCB / ST21NFCC, NCI protocol, I2C **and** SPI.
  Registers with the kernel NFC netlink subsystem → this is the driver
  `neard` talks to.
- `st21nfca/` — older ST21NFCA, HCI (not NCI).
- Kernel config today: `CONFIG_NFC=m`, `CONFIG_NFC_NCI=m`, and the
  **NXP** NCI drivers are enabled (`CONFIG_NFC_NXP_NCI_I2C=m`) — wrong
  vendor. `CONFIG_NFC_ST_NCI` / `CONFIG_NFC_ST_NCI_I2C` are **not set**.
- The NFC subsystem is lightly maintained (under netdev, maintainer
  K. Kozlowski) but **not** being removed.

## 4. Architecture options

**Path A — `st-nci` + `neard` (recommended, mainline-native).**
Enable `CONFIG_NFC_ST_NCI` + `CONFIG_NFC_ST_NCI_I2C`; add the NFC node
to `&i2c2`. The ST21NFC CLF speaks standard NCI; `st-nci` is the ST NCI
transport. Risk: `st-nci` targets the older ST21NFCB/C — the ST54J CLF
(ST21NFCD-class) may need a new compatible string and small init
quirks (e.g. the double-pulse reset). Upstreamable. Works with `neard`
(packaged in Alpine `edge/testing`) and `nfctool`.

**Path B — port downstream `st21nfc.c` + `libnfc-nci` (fallback).**
Port the GPL-2.0 char-device driver as-is; pair with a userspace NCI
stack. Matches Android exactly, but `libnfc-nci` is NXP-PN71xx-oriented
and would need ST's variant; does **not** integrate with `neard`/
mainline tooling. Use only if Path A's `st-nci` can't be made to bind.

**Path C — minimal NCI-I2C transport driver.**
Write a ~300-line transport modelled on `st-nci/i2c.c`, no firmware
path. Only worth it if `st-nci`'s ST-specific init actively fights the
ST54J CLF.

## 5. Proposed bringup plan (coding phase)

Following the `hardware-driver-bringup` pipeline:

1. **Userspace test harness first.** Static `i2c` tool: assert reset
   (gpio67) via `/dev/gpiochip`, `i2cdetect` `&i2c2` for addr 0x08,
   send NCI `CORE_RESET` + `CORE_INIT`, read back the manufacturer ID.
   This confirms the chip is alive and on NCI before any kernel work.
2. **DTS node** — replace the `/* st21nfc nfc@8 */` placeholder in
   `sm7150-google-sunfish.dts` with a real node (reset/irq gpios at
   minimum).
3. **Kernel config** — drop the NXP NCI symbols, add
   `CONFIG_NFC_ST_NCI=m` + `CONFIG_NFC_ST_NCI_I2C=m`.
4. **Driver** — try `st-nci` as-is; if it won't bind, add an
   `st,st21nfcd` / `st,st21nfc` compatible + the double-pulse reset
   quirk, cross-checking against downstream `st21nfc.c`.
5. **Userspace** — `apk add neard`; verify with `nfctool` reading a
   real NFC tag. That is the success criterion.
6. Keep the userspace harness — it verifies the kernel driver emits
   identical wire bytes.

## 6. Decompilation — what Ghidra is and isn't useful for

The original plan was to Ghidra the stock binaries to "get NFC
working." Most of that is unnecessary:

- **Kernel driver** — full GPL-2.0 C source (`st21nfc.c`). Reading C
  beats decompiling, always. **Skip Ghidra here.**
- **NFC HAL** (`android.hardware.nfc@1.2-service.st`) — ST publishes an
  open reference: `github.com/STMicroelectronics/ST54-android-vendor-st21nfc`,
  plus `libnfc-nci`. Decompilation only worthwhile if a specific ST
  proprietary init quirk can't be found in the open sources.
- **CLF firmware-update image** — closed ST blob. Not needed for tag
  read/write (CLF self-boots from ROM). Ghidra could help only if you
  later want to *update* the CLF firmware.
- **eSE / secure-element applet** — closed, and irrelevant: payments
  are blocked by attestation regardless, so reversing it yields nothing
  usable.

Net: decompilation is at most a niche tool for the firmware-update path,
not the bringup path.

## 7. Documentation sources

- Protocol: **NFC Forum NCI spec** (current v2.3) —
  `nfc-forum.org/build/specifications`. NCI 1.0/2.0 PDFs circulate
  freely and are sufficient. This is the documented interface boundary;
  the ST54J datasheet itself is NDA-locked and **not needed**.
- ST open driver/HAL: `github.com/STMicroelectronics/ST54-android-kernel`,
  `…/ST54-android-vendor-st21nfc`.
- Cross-vendor NCI-I2C reference: `github.com/NXPNFCLinux/linux_libnfc-nci`,
  NXP app notes AN11697 / AN13287 (PN7160 Linux porting) — generic NCI
  guidance, vendor mismatch is fine for protocol-level study.

## 8. The chip's full feature set — and what reaches Linux

ST54J is three dies in one package: the **ST21NFC CLF** (the NFC radio),
the **ST54J eSE** (secure element), and an **eSIM/eUICC**.

### NFC radio (ST21NFC CLF) — ST21NFCJ class, Cortex-M3 @ 56 MHz, NCI 2.0

Reader / poll mode:
- NFC-A (ISO 14443A), NFC-B (ISO 14443B), NFC-F (FeliCa), NFC-V
  (ISO 15693), ISO 18092, Kovio barcode. 106 / 212 / 424 kbps.
- NFC Forum tag types 1–5 read/write. MIFARE Ultralight / DESFire.
  MIFARE Classic = license-gated (NXP crypto1 IP, may not be enabled).
- ISO-DEP APDU transceive (smartcards, DESFire, e-passport).

Card emulation (listen) mode:
- NFC-A / NFC-B / NFC-F card emulation, ISO-DEP listen.
- HCE (host card emulation) or off-host routing to the eSE.

Peer-to-peer: NFC-DEP initiator + target (deprecated tech).

Low-power: LPCD / wake-on-NFC autonomous polling loop; wake sources =
I2C, timer, GPIO, RF-field detect, tag detect.

Antenna / RF: active load modulation (small / metal-frame antennas),
dynamic RF power, ~1.3 W TX, antenna self-check — all automatic in the
CLF firmware, transparent to the host.

Firmware: eFlash, secure signed update, loader / recovery mode
(`CORE_RESET_NTF` reason byte `0xA1`).

### Chip capability -> Linux reachability

| Chip capability | Chip | st-nci + neard | st21nfc.c + libnfc-nci |
|-|-|-|-|
| Read/write NDEF tags T1-5, read UIDs | yes | yes | yes |
| ISO-DEP APDU to a tag / smartcard | yes | no (raw socket only) | yes |
| Card emulation / HCE | yes | NO — net/nfc has no CE path | yes |
| Route CE to the eSE | yes | dormant | yes, but eSE is locked |
| Peer-to-peer / SNEP | yes | yes (deprecated) | yes (deprecated) |
| Wake-on-NFC | yes | needs small driver patch | usually wired |
| Raw NCI / proprietary ST cmds | yes | predefined vendor cmds only | yes |
| Active load modulation, dynamic RF | yes | automatic | automatic |
| CLF firmware update | yes | needs closed ST blob | needs closed ST blob |
| Contactless payments | yes | NO | NO |

### eSE — capable but permanently locked

ST33-based (SC300 SecurCore), JavaCard + GlobalPlatform 2.3, CC EAL5+,
EMVCo certified. Reachable from Linux over SPI (port `st54j_se.c`,
~300 lines, or use spidev) — you can send raw APDUs. But every
privileged operation needs an SCP02/SCP03 secure channel using the
**ISD keys, owned by Google**; the card manager is locked at
manufacturing. You cannot install applets, cannot use it as a key
store, cannot do payments (also blocked by Play Integrity attestation).
On postmarketOS the eSE is, in practice, **dead silicon**.

### eSIM — out of NFC scope

ISO-7816 eUICC reachable via the modem; profile keys are GSMA / carrier
controlled. Not freely programmable; not part of the NFC bringup.

### Net: realistic NFC scope on this phone

Reader/writer (all tag types, NDEF, ISO-DEP APDU) and host card
emulation are achievable. The eSE and contactless payments are not — a
hard hardware/policy wall, not a software gap.

## 9. Userspace bringup — results (Phase 2, WORKING)

A standalone static aarch64 harness `nfc/stnfc.c` talks raw NCI over
I2C and has verified, on-device (kernel 7.1.0-rc3-sm7150):

- ST21NFC alive on NCI 2.0 — `/dev/i2c-2` slave `0x08`, Manufacturer
  ID `0x02` (STMicroelectronics).
- TLMM = `gpiochip2` (`3500000.pinctrl`). reset/VEN = line 67,
  IRQ/host-int = line 37, documented active-high polarity (no
  inversion). Double-pulse hardware reset works.
- MIFARE Classic 1K detected and identified: UID `b0 38 f8 e1`,
  ATQA `04 00`, SAK `0x08`, RF protocol `0x90`.

Access: no `doas` on this rootfs — `echo 1234 | sudo -S`; SSH via
`sshpass` (no key installed). Tool needs root (`user` not in i2c/gpio
groups). Cross-built with `aarch64-linux-gnu-gcc -O2 -static`.

### The working NCI init sequence (hard-won)

`CORE_RESET`/`CORE_INIT` alone do **not** energize the RF — the ST
chip boots with its RF subsystem powered down. Required order:

```
1. hardware reset: VEN/reset GPIO low 20ms / high (double-pulse)
2. wait for the unsolicited CORE_RESET_NTF (chip booted)
3. CORE_RESET_CMD       20 00 01 01
4. CORE_INIT_CMD        20 01 02 00 00
5. PROP_NFC_MODE_SET    2F 02 02 02 01     <- ST-proprietary RF enable
6. chip self-resets, re-emits CORE_RESET_NTF (reason 0xA0)
7. CORE_INIT_CMD again  20 01 02 00 00     <- mandatory second init
8. RF_DISCOVER_MAP      21 00 10 05 ...    (standard protocols only)
9. RF_DISCOVER          21 03 09 04 00 01 01 01 02 01 06 01
```

Gotchas found:
- First I2C write after reset can return `ENXIO` while the chip is
  still booting — retry the write.
- A proprietary MIFARE map entry (`80 01 01`) in `RF_DISCOVER_MAP` is
  **rejected** (status `01`) — map only standard protocols; an
  unmapped MIFARE tag still surfaces via `RF_INTF_ACTIVATED_NTF` /
  `RF_DISCOVER_NTF` carrying the UID.
- ST proprietary notifications `6F 05` / `6F 06` are benign RF
  reader-session start/stop heartbeats.

### MIFARE Classic 1K read + write — WORKING

crypto1 IS supported by the ST CLF (ST themselves authored the AOSP
`rw_mfc.cc` driver). Tag operations are NCI DATA packets on conn 0
(header `00 00 LL`), after `RF_INTF_ACTIVATED_NTF` (RF interface/proto
`0x90`). The ST frame order differs from NXP's:

```
authenticate  00 00 0C  60 <blk> <UID 4> <keyA 6>   -> 1-byte DATA 00 = OK
read block    00 00 02  30 <blk>                    -> 16-byte DATA = block
write block   00 00 12  A0 <blk> <16 data bytes>    -> 1-byte DATA 00 = OK
```

Key points:
- AUTH key/UID order is `UID then key` (ST); NXP uses `key then UID`
  and a `40`-prefixed opcode — sending the NXP form gets `0xB1`.
- WRITE is a SINGLE packet (`A0 blk` + 16 bytes together); the 0x90
  interface sequences the two MIFARE air-phases itself. A split
  two-phase write (`A0 blk` alone first) is rejected with `0xB3`.
- NCI status `0xB0`/`B1`/`B2`/`B3` = RF transmission / protocol /
  timeout / unexpected-data errors.
- `stnfc read [blk cnt]` and `stnfc write <blk> [hex]` implement this;
  `write` refuses block 0 and sector trailers (brick guard) and
  verifies by read-back.

Verified on the user's factory-blank MIFARE Classic 1K (UID
b0 38 f8 e1): sector 0 fully read; block 1 written + read-back
matched.

### Card emulation (Type 4 NDEF tag) — WORKING

Verified on-device 2026-05-23: another Android phone successfully
read the full URL payload from the Pixel 4a acting as an NFC tag.

Listen-mode setup the chip accepts:
```
RF_DISCOVER_MAP   21 00 04  01  04 02 02   (ISO-DEP, mode=listen, intf=ISO-DEP)
RF_DISCOVER       21 03 03  01  80 01      (NFC-A passive listen)
```

The chip emits **no `6F 05/06` heartbeats during listen** (those are
poll-cycle markers). On a reader tap an `RF_INTF_ACTIVATED_NTF` with
tech `0x80` arrives, then APDUs flow as NCI DATA packets on conn 0:

```
reader -> 00 A4 04 00 07 D2 76 00 00 85 01 01 00   SELECT NDEF app AID
reader -> 00 A4 00 0C 02 E1 03                      SELECT CC file
reader -> 00 B0 00 00 0F                            READ CC (15 bytes)
reader -> 00 A4 00 0C 02 E1 04                      SELECT NDEF file
reader -> 00 B0 00 00 02                            READ NLEN (2 bytes)
reader -> 00 B0 00 02 <len>                         READ NDEF message
host   -> response bytes + 90 00 for each
```

Notes:
- The chip's default LA_SEL_INFO already advertises ISO-DEP — no
  `CORE_SET_CONFIG` needed for a basic Type 4 emulator.
- The `0x90` proprietary MIFARE interface is irrelevant to CE; ISO-DEP
  listen uses the standard `0x02` ISO-DEP interface.
- `stnfc emulate-ndef [url|text]` implements this with a small APDU
  state machine (SELECT AID / SELECT CC / SELECT NDEF / READ BINARY).
- The CLF + this approach do not support MIFARE Classic emulation
  (an extremely rare CLF feature), but Type 4 ISO-DEP listen covers
  all standard tag-emulation use cases.

### Programmable HCE — WORKING

`stnfc emulate-apdu <conf-file>` extends the emulator into a generic
ISO-DEP listen target driven by a rule table. The config syntax is
`HEX_PATTERN [*] : HEX_RESPONSE`; first match wins, default response
is `6A 82`. A trailing `*` in the pattern means prefix-match.

Verified end-to-end with a config that reproduces a Type 4 NDEF tag
via 7 rules — another phone successfully read the NDEF payload across
8 reader taps / 24 APDU exchanges. The same engine emulates any
ISO-DEP-listen card: SELECT AID + arbitrary APDU responses, AID
routing, custom return data.

### Full userspace tool feature matrix

`~/sunfish-bringup/nfc/stnfc.c` (~1560 lines, single-file static
aarch64 binary; drives `/dev/i2c-2` + GPIO chardev directly, NO kernel
NFC driver in the path):

| subcommand | tested on-device | covers |
|-|-|-|
| `info / reset / nci / drain / raw` | yes | low-level chip control, debug |
| `poll` | yes | tag detect, UID, type, RF protocol |
| `read [blk cnt]` | yes | MIFARE Classic auth (key A FF*6) + block read |
| `write blk [hex]` | yes | MIFARE Classic single block write + verify |
| `dump` | yes | full MIFARE Classic 1K (64/64 blocks) |
| `apdu HH HH ...` | yes | ISO-DEP APDU transceive (identified NXP MIFARE DESFire EV1 4K) |
| `ndef-read` | partial | Type 2 + Type 4 dispatch, APDU flow proven (no NDEF-formatted tag handy to verify final parse) |
| `ndef-write <text>` | n/a | Type 2 NTAG write (no NTAG to verify) |
| `emulate-ndef [url]` | yes | Type 4 NDEF tag emulation; reader read 41-byte URL payload |
| `emulate-apdu <conf>` | yes | programmable HCE, 24 APDUs handled across 8 taps |

## 10. Kernel driver — assessment

Userspace NFC works with no kernel NFC driver. A kernel driver adds
OS integration (neard / the NFC subsystem) and resource/power
management. Reading `drivers/nfc/st-nci/` revealed:

- `st-nci` is **NDLC-link-layer based**: `ndlc_send()` prepends a
  1-byte PCB (`0x84`) to every frame; the read path strips a PCB.
  Built for ST21NFCB / ST21NFCC.
- The ST54J's ST21NFC speaks **plain NCI** over I2C (no NDLC) —
  proven: the `stnfc` tool's raw `20 00 01 01` works; an NDLC chip
  would treat `0x20` as a supervisor frame.
- `st_nci_init()` already sends an ST "set NFC mode" via
  `nci_prop_cmd(ST_NCI_CORE_PROP=0x01, {0x02,mode})` → wire
  `2F 01 02 02 01`. The ST21NFC needs OID **0x02**: `2F 02 02 02 01`.
- The mode-set makes the ST21NFC **self-reset** (re-emits
  `CORE_RESET_NTF`); the NCI-core open sequence
  (CORE_RESET → CORE_INIT → `ops.init`) does not expect that.

So "adapt st-nci" really means a de-NDLC refactor. Cleaner options,
all "mainline NCI driver + neard":
- **New plain-NCI-I2C driver** modeled on `nxp-nci/i2c.c`:
  `nci_allocate_device` + `nci_ops` (open = reset gpio + irq enable,
  send = plain `i2c_master_send`, init = ST mode-set) + threaded IRQ
  → `nci_recv_frame`. ~300 lines, cleanest, upstreamable.
- De-NDLC `st-nci` in place (touches shared `core.c`).
- Port downstream char-device `st21nfc.c` + `libnfc-nci` (not neard).

DTS (either way): node on `&i2c2`, `compatible="st,st21nfc"`,
`reg=<0x08>`, reset = `<&tlmm 67>`, irq via `<&tlmm 37>`.
Open question to solve in the driver: the post-mode-set self-reset
vs the NCI-core open flow.
