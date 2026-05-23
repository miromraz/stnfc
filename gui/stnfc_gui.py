#!/usr/bin/env python3
# stnfc GUI -- GTK4 + libadwaita frontend that drives the stnfc CLI.
#
# Built with PyGObject. Mobile-touch friendly via Adw.PreferencesGroup /
# Adw.ActionRow widgets, with a four-tab layout (Read / Write / Emulate /
# Tools) navigated via Adw.ViewSwitcherBar. A persistent output panel
# at the bottom streams stnfc stdout live across all tabs.
#
# Permissions: stnfc needs root for /dev/i2c-2 and /dev/gpiochip2. The
# GUI invokes it via `sudo -n` (set up /etc/sudoers.d/stnfc with
# NOPASSWD). Environment overrides:
#   STNFC       path to the stnfc binary (default /usr/local/bin/stnfc)
#   STNFC_SUDO  command to escalate with (default 'sudo'; empty = none)
#
# Why GTK4/Adw and not Qt? pmOS edge currently ships py3-pyside6 6.11.0
# built against Qt 6.11.0, but the installed Qt is 6.11.1 -- private-ABI
# version skew that crashes every PySide6 import. The QWidgets port is
# preserved in stnfc_gui_qt.py for when Alpine's rebuild lands.

import os
import sys

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

STNFC = os.environ.get("STNFC", "/usr/local/bin/stnfc")
SUDO = os.environ.get("STNFC_SUDO", "sudo")


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_default_size(420, 760)
        self.set_title("stnfc")
        self.proc = None

        # ----- toolbar + header --------------------------------------
        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)

        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle(
            title="stnfc", subtitle="NFC toolkit for sunfish"))
        toolbar.add_top_bar(header)

        self.stop_btn = Gtk.Button.new_from_icon_name("process-stop-symbolic")
        self.stop_btn.set_tooltip_text("Stop running command")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self.on_stop)
        header.pack_end(self.stop_btn)
        clear_btn = Gtk.Button.new_from_icon_name("edit-clear-all-symbolic")
        clear_btn.set_tooltip_text("Clear output")
        clear_btn.connect("clicked", self.on_clear)
        header.pack_end(clear_btn)

        # ----- main vertical: ViewStack on top, output below ---------
        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        toolbar.set_content(main)

        self.stack = Adw.ViewStack()
        self.stack.set_vexpand(True)
        main.append(self.stack)

        self.stack.add_titled_with_icon(self._build_read_page(),
            "read", "Read", "edit-find-symbolic")
        self.stack.add_titled_with_icon(self._build_write_page(),
            "write", "Write", "document-edit-symbolic")
        self.stack.add_titled_with_icon(self._build_emulate_page(),
            "emulate", "Emulate", "send-to-symbolic")
        self.stack.add_titled_with_icon(self._build_tools_page(),
            "tools", "Tools", "applications-utilities-symbolic")

        # output (shared across tabs)
        out_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4,
                          margin_top=4, margin_bottom=4,
                          margin_start=8, margin_end=8)
        out_lbl = Gtk.Label(label="<b>Output</b>", use_markup=True,
                            halign=Gtk.Align.START)
        out_box.append(out_lbl)
        self.tv_out = Gtk.TextView(editable=False, cursor_visible=False,
                                    monospace=True)
        self.tv_out.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._out_scroll = Gtk.ScrolledWindow(min_content_height=180)
        self._out_scroll.add_css_class("card")
        self._out_scroll.set_child(self.tv_out)
        out_box.append(self._out_scroll)
        main.append(out_box)
        self.buffer = self.tv_out.get_buffer()

        # ----- bottom view switcher (Adwaita "tabbar") ---------------
        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)
        toolbar.add_bottom_bar(switcher)

        self.append("Ready.  CLI: " + STNFC + "\n"
                    "Pick a tab and tap an action.  Tag operations need\n"
                    "the tag near the upper-center of the phone's back.\n")

    # ===== page builders ============================================

    def _scroll_box(self):
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                      margin_top=12, margin_bottom=12,
                      margin_start=12, margin_end=12)
        scroll.set_child(box)
        return scroll, box

    def _action(self, group, title, subtitle, args, icon="go-next-symbolic"):
        row = Adw.ActionRow(title=title, subtitle=subtitle, activatable=True)
        row.add_suffix(Gtk.Image.new_from_icon_name(icon))
        row.connect("activated", lambda *_: self.run(args))
        group.add(row)
        return row

    def _build_read_page(self):
        scroll, box = self._scroll_box()
        g = Adw.PreferencesGroup(title="Detect")
        box.append(g)
        self._action(g, "Poll for tag",
            "Print UID, tag type, RF protocol", ["poll"])
        self._action(g, "Read NDEF",
            "Parse NDEF from Type 2 / Type 4 tag", ["ndef-read"])

        g2 = Adw.PreferencesGroup(title="MIFARE Classic")
        box.append(g2)
        self._action(g2, "Dump 1K",
            "Auth all 16 sectors (key A FF*6) and read 64 blocks",
            ["dump"])
        return scroll

    def _build_write_page(self):
        scroll, box = self._scroll_box()
        g = Adw.PreferencesGroup(title="MIFARE Classic — block write",
            description="Block 0 (UID) and sector trailers are guarded")
        box.append(g)
        self.write_row = Adw.EntryRow(title="Text to write to block 1 (up to 16 chars)")
        self.write_row.set_show_apply_button(True)
        self.write_row.connect("apply", self.on_write_block1)
        g.add(self.write_row)

        g2 = Adw.PreferencesGroup(title="NDEF write (Type 2 / NTAG)",
            description="Write a URL or text NDEF record to a Type 2 tag")
        box.append(g2)
        self.ndef_write_row = Adw.EntryRow(title="URL or text")
        self.ndef_write_row.set_show_apply_button(True)
        self.ndef_write_row.connect("apply", self.on_ndef_write)
        g2.add(self.ndef_write_row)
        return scroll

    def _build_emulate_page(self):
        scroll, box = self._scroll_box()

        g_url = Adw.PreferencesGroup(title="URL or text tag")
        box.append(g_url)
        self.url_row = Adw.EntryRow(
            title="URL (https://, tel:, mailto:, geo:) or plain text")
        self.url_row.set_show_apply_button(True)
        self.url_row.connect("apply", self.on_emit_url)
        g_url.add(self.url_row)

        g_wifi = Adw.PreferencesGroup(title="Wi-Fi sharing",
            description="Tap a receiver phone — it auto-joins the named network")
        box.append(g_wifi)
        self.wifi_ssid = Adw.EntryRow(title="SSID")
        g_wifi.add(self.wifi_ssid)
        self.wifi_psk = Adw.PasswordEntryRow(title="Password (empty = open)")
        g_wifi.add(self.wifi_psk)
        wifi_emit = Adw.ActionRow(title="Emulate Wi-Fi tag (60 s)",
            activatable=True)
        wifi_emit.add_suffix(Gtk.Image.new_from_icon_name(
            "network-wireless-symbolic"))
        wifi_emit.connect("activated", self.on_emit_wifi)
        g_wifi.add(wifi_emit)
        return scroll

    def _build_tools_page(self):
        scroll, box = self._scroll_box()

        g = Adw.PreferencesGroup(title="Clone and replay",
            description="Capture a tag, then replay it from this phone")
        box.append(g)
        self._action(g, "Clone tag",
            "Read everything readable, save to /tmp/clone.conf",
            ["clone", "/tmp/clone.conf"],
            icon="edit-copy-symbolic")
        self._action(g, "Emulate cloned tag (60 s)",
            "Replay /tmp/clone.conf as a Type 4 tag",
            ["--timeout", "60000", "emulate-apdu", "/tmp/clone.conf"],
            icon="media-playback-start-symbolic")

        g_mfc = Adw.PreferencesGroup(title="MIFARE clone-to-tag")
        box.append(g_mfc)
        self._action(g_mfc, "Copy /tmp/clone.conf to current tag",
            "Writes a MIFARE dump to the tag (skips block 0 and trailers)",
            ["mfc-copy", "/tmp/clone.conf"],
            icon="document-save-symbolic")

        g_diag = Adw.PreferencesGroup(title="Diagnostics")
        box.append(g_diag)
        self._action(g_diag, "Chip info",
            "List gpiochips, identify TLMM, show CLI config",
            ["info"])
        self._action(g_diag, "NCI handshake",
            "Reset + CORE_RESET + CORE_INIT, print chip identity",
            ["nci"])
        return scroll

    # ===== output / subprocess plumbing =============================

    def append(self, text):
        end = self.buffer.get_end_iter()
        self.buffer.insert(end, text)
        adj = self._out_scroll.get_vadjustment()
        GLib.idle_add(lambda: adj.set_value(adj.get_upper()) or False)

    def run(self, args):
        if self.proc:
            self.append("[busy — another command is running]\n")
            return
        cmd = ([SUDO, "-n", STNFC] if SUDO else [STNFC]) + list(args)
        self.append("\n$ " + " ".join(cmd) + "\n")
        try:
            self.proc = Gio.Subprocess.new(
                cmd,
                Gio.SubprocessFlags.STDOUT_PIPE
                | Gio.SubprocessFlags.STDERR_MERGE,
            )
        except GLib.Error as exc:
            self.append("[error: " + exc.message + "]\n")
            self.proc = None
            return
        self.stop_btn.set_sensitive(True)
        stream = Gio.DataInputStream.new(self.proc.get_stdout_pipe())
        self._read_next(stream)

    def _read_next(self, stream):
        stream.read_line_async(
            GLib.PRIORITY_DEFAULT, None, self._on_line, stream)

    def _on_line(self, stream, result, _data):
        try:
            line, _length = stream.read_line_finish_utf8(result)
        except GLib.Error:
            line = None
        if line is None:
            rc = "?"
            try:
                rc = self.proc.get_exit_status() if self.proc else "?"
            except Exception:
                pass
            self.append("[stnfc exit " + str(rc) + "]\n")
            self.proc = None
            self.stop_btn.set_sensitive(False)
            return
        self.append(line + "\n")
        self._read_next(stream)

    # ===== actions ==================================================

    def on_stop(self, _btn):
        if self.proc:
            self.proc.force_exit()
            self.append("[terminate signal sent]\n")

    def on_clear(self, _btn):
        self.buffer.set_text("")

    def on_emit_url(self, row):
        text = row.get_text().strip()
        if text:
            self.run(["--timeout", "60000", "emulate-ndef", text])
            row.set_text("")

    def on_emit_wifi(self, _row):
        ssid = self.wifi_ssid.get_text().strip()
        if not ssid:
            self.append("[wifi: SSID is required]\n")
            return
        psk = self.wifi_psk.get_text()
        args = ["--timeout", "60000", "emulate-wifi", ssid]
        if psk:
            args.append(psk)
        else:
            args.extend(["", "OPEN"])
        self.run(args)

    def on_write_block1(self, row):
        text = row.get_text()
        if not text:
            return
        data = text.encode("utf-8")[:16].ljust(16, b"\x00")
        hex_args = ["%02X" % b for b in data]
        self.run(["write", "1"] + hex_args)
        row.set_text("")

    def on_ndef_write(self, row):
        text = row.get_text().strip()
        if text:
            self.run(["ndef-write", text])
            row.set_text("")


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id="io.github.miromraz.stnfc",
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", self.on_activate)

    def on_activate(self, _app):
        win = self.props.active_window or Window(self)
        win.present()


def main():
    sys.exit(App().run(sys.argv))


if __name__ == "__main__":
    main()
