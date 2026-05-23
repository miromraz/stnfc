# stnfc GUI

A Plasma-Mobile-friendly GUI frontend that wraps the `stnfc` CLI.

Two implementations live here:

| File | Toolkit | Status on pmOS edge (May 2026) |
|-|-|-|
| `stnfc_gui.py` | **GTK4 + libadwaita (PyGObject)** — default | works |
| `stnfc_gui_qt.py` | PySide6 (Qt 6) | broken — see below |

The PySide6 version is preserved as a fallback. pmOS edge currently
ships `py3-pyside6` 6.11.0 built against Qt 6.11.0, but the installed
Qt is 6.11.1 — a private-ABI version skew (`QtPrivate_6_11_0` symbol
not found). When PySide6 is rebuilt against the installed Qt the Qt
version will work again; until then GTK4 is the default.

## Install (on the phone)

```sh
# the stnfc CLI -- assumes you've built and scp'd the binary
sudo install -m 755 ./stnfc /usr/local/bin/stnfc

# passwordless sudo for stnfc only
echo '%wheel ALL=(root) NOPASSWD: /usr/local/bin/stnfc' | \
    sudo tee /etc/sudoers.d/stnfc
sudo chmod 0440 /etc/sudoers.d/stnfc

# the GTK GUI
sudo install -m 755 ./gui/stnfc_gui.py /usr/local/bin/stnfc-gui
sudo install -m 644 ./gui/io.github.miromraz.stnfc.desktop \
    /usr/share/applications/

# GTK4 / libadwaita / PyGObject (typically already present on pmOS
# Plasma Mobile -- install only if missing):
sudo apk add gtk4.0 libadwaita py3-gobject3
```

## Running

From the Plasma Mobile app launcher, find **stnfc** and tap. The
desktop entry inherits the session env (Wayland, D-Bus, etc.) so the
window opens cleanly.

To launch from SSH (e.g. for remote debugging) the env vars need to
be set explicitly:

```sh
DBUS=$(tr '\0' '\n' < /proc/$(pgrep -f 'kwin_wayland --wayland-fd' \
    | head -1)/environ | grep '^DBUS_SESSION_BUS_ADDRESS=' | cut -d= -f2-)
WAYLAND_DISPLAY=wayland-0 \
  XDG_RUNTIME_DIR=/run/user/$(id -u) \
  GDK_BACKEND=wayland \
  XDG_CURRENT_DESKTOP=KDE \
  DBUS_SESSION_BUS_ADDRESS="$DBUS" \
  /usr/local/bin/stnfc-gui
```

## Environment knobs

| variable | default | meaning |
|-|-|-|
| `STNFC` | `/usr/local/bin/stnfc` | path to the CLI binary |
| `STNFC_SUDO` | `sudo` | command to escalate with (set empty if `stnfc` is setuid root) |

## UI layout

| Section | Actions |
|-|-|
| Read | Detect tag · Read NDEF · Dump MIFARE Classic 1K |
| Emulate | Inline entry: URL or text → `emulate-ndef` for 60 s |
| Clone and replay | Clone tag to `/tmp/clone.conf` · Replay that file (60 s) |
| Write | Inline entry: text → `write` to MIFARE block 1 |
| Output | Live-streamed `stnfc` stdout/stderr; clear-output and stop-command buttons in the headerbar |

For power-user operations (`apdu`, `mfc-copy`, `raw`, `dump > file`,
custom blocks) drop to the CLI:

```sh
sudo stnfc apdu 90 60 00 00 00
sudo stnfc mfc-copy /tmp/src.dump
sudo stnfc --timeout 60000 emulate-apdu /path/to/file.conf
```
