# stnfc GUI

A small Plasma-Mobile-friendly Qt frontend that wraps the `stnfc` CLI.

Single-file PySide6 (Qt 6) Python app. Each button spawns the `stnfc`
binary as a subprocess and streams its output into the on-screen log.
For UX iteration speed; can later be ported to Kirigami QML for a more
native Plasma Mobile look.

## Buttons

|  |  |
|-|-|
| Read tag (poll) | `stnfc poll` — detect a tag, print UID/SAK/RF protocol |
| Read NDEF | `stnfc ndef-read` — parse and pretty-print NDEF |
| Dump MIFARE 1K | `stnfc dump` — auth all 16 sectors, read 64/64 blocks |
| Clone tag | `stnfc clone /tmp/clone.conf` — capture for replay |
| Emulate cloned | `stnfc emulate-apdu /tmp/clone.conf` — replay the clone for 60 s |
| Emulate URL / text | `stnfc emulate-ndef <text>` — phone becomes a Type 4 NDEF tag |
| MIFARE write block | `stnfc write <blk> <hex>` — block-level write (safety-guarded) |
| MIFARE copy from dump | `stnfc mfc-copy <file>` — write a dump to a fresh tag |
| Stop running command | sends SIGTERM to the running `stnfc` subprocess |

## Requirements (on the phone)

- `stnfc` binary built from `tool/stnfc.c` and copied somewhere in `$PATH`
  (the GUI defaults to looking up `stnfc`; override via `STNFC=/path/to/stnfc`).
- Python 3 + PySide6:

```
sudo apk add python3 py3-pyside6
```

## Running

```
python3 stnfc_gui.py
```

## Permissions — `stnfc` needs root

`stnfc` opens `/dev/i2c-2` and `/dev/gpiochip2`, both of which are
root-only on a stock pmOS. The GUI runs the binary via `sudo -n`
(non-interactive) by default. Two ways to make that work:

**Passwordless sudo for stnfc only** (cleanest):

```
# as root
echo '%wheel ALL=(root) NOPASSWD: /usr/local/bin/stnfc' \
    > /etc/sudoers.d/stnfc
chmod 0440 /etc/sudoers.d/stnfc
```

**Setuid the binary** (simplest, less safe — only a test phone):

```
sudo chown root:root /usr/local/bin/stnfc
sudo chmod u+s /usr/local/bin/stnfc
# then run the GUI with sudo disabled:
STNFC_SUDO= python3 stnfc_gui.py
```

A future improvement (better than either): a udev rule giving a non-root
group read/write access to the two devices, then add the user to the
group. Lives in `packaging/alpine/` once the apk is wired up.

## Environment knobs

| variable | default | meaning |
|-|-|-|
| `STNFC` | `stnfc` | path to the `stnfc` binary |
| `STNFC_SUDO` | `sudo` | command to escalate with (set empty to disable) |
