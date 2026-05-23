#!/usr/bin/env python3
# stnfc GUI -- GTK4 + libadwaita frontend that drives the stnfc CLI.
#
# Built with PyGObject. Mobile-touch friendly via Adw.PreferencesGroup /
# Adw.ActionRow. Each user action spawns the stnfc binary as a subprocess
# (via Gio.Subprocess for async output streaming) and appends its output
# to the on-screen log.
#
# Why GTK4/Adw and not Qt? pmOS edge currently ships a PySide6 6.11.0
# built against Qt 6.11.0 while the installed Qt is 6.11.1 -- a private-
# ABI break that crashes any PySide6 import. The QWidgets version of
# this GUI is preserved in stnfc_gui_qt.py for when that's fixed.
#
# Permissions: stnfc needs root for /dev/i2c-2 and /dev/gpiochip2. The
# GUI invokes it via `sudo -n` by default (set up /etc/sudoers.d/stnfc
# with NOPASSWD). Environment overrides:
#   STNFC       path to the stnfc binary    (default /usr/local/bin/stnfc)
#   STNFC_SUDO  command to escalate with    (default 'sudo'; empty = none)

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

        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)

        header = Adw.HeaderBar()
        title = Adw.WindowTitle(title="stnfc",
                                subtitle="NFC toolkit for sunfish")
        header.set_title_widget(title)
        toolbar.add_top_bar(header)

        self.stop_btn = Gtk.Button.new_from_icon_name("process-stop-symbolic")
        self.stop_btn.set_tooltip_text("Stop running command")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self.on_stop)
        header.pack_end(self.stop_btn)

        clear_btn = Gtk.Button.new_from_icon_name(
            "edit-clear-all-symbolic")
        clear_btn.set_tooltip_text("Clear output")
        clear_btn.connect("clicked", self.on_clear)
        header.pack_end(clear_btn)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        toolbar.set_content(scroll)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                        margin_top=12, margin_bottom=12,
                        margin_start=12, margin_end=12)
        scroll.set_child(outer)

        # -------- READ group --------------------------------------------
        g_read = Adw.PreferencesGroup(title="Read")
        outer.append(g_read)
        self._add_action(g_read, "Detect tag",
                         "Print UID, tag type, RF protocol",
                         ["poll"])
        self._add_action(g_read, "Read NDEF",
                         "Parse the NDEF message from a Type 2 / Type 4 tag",
                         ["ndef-read"])
        self._add_action(g_read, "Dump MIFARE Classic 1K",
                         "Auth all 16 sectors with key A FF×6, read 64 blocks",
                         ["dump"])

        # -------- EMULATE group -----------------------------------------
        g_emu = Adw.PreferencesGroup(title="Emulate")
        outer.append(g_emu)
        self.url_row = Adw.EntryRow(title="URL or text — phone becomes an NFC tag")
        self.url_row.set_show_apply_button(True)
        self.url_row.connect("apply", self.on_emit_url)
        g_emu.add(self.url_row)

        # -------- WI-FI SHARING group -----------------------------------
        g_wifi = Adw.PreferencesGroup(title="Share Wi-Fi",
            description="Phone becomes a tag carrying Wi-Fi credentials")
        outer.append(g_wifi)
        self.wifi_ssid = Adw.EntryRow(title="SSID")
        g_wifi.add(self.wifi_ssid)
        self.wifi_psk = Adw.PasswordEntryRow(title="Password (leave empty = open)")
        g_wifi.add(self.wifi_psk)
        wifi_btn_row = Adw.ActionRow(title="Emulate Wi-Fi tag",
            subtitle="Receiver phone joins on tap (60 s window)",
            activatable=True)
        wifi_btn_row.add_suffix(Gtk.Image.new_from_icon_name("network-wireless-symbolic"))
        wifi_btn_row.connect("activated", self.on_emit_wifi)
        g_wifi.add(wifi_btn_row)

        # -------- CLONE / REPLAY group ----------------------------------
        g_cln = Adw.PreferencesGroup(title="Clone and replay",
            description="Capture a tag, then replay it from this phone")
        outer.append(g_cln)
        self._add_action(g_cln, "Clone tag",
                         "Read everything readable, save to /tmp/clone.conf",
                         ["clone", "/tmp/clone.conf"])
        self._add_action(g_cln, "Emulate cloned tag (60 s)",
                         "Replay /tmp/clone.conf — tap a reader to test",
                         ["--timeout", "60000",
                          "emulate-apdu", "/tmp/clone.conf"])

        # -------- WRITE group -------------------------------------------
        g_wr = Adw.PreferencesGroup(title="Write",
            description="MIFARE Classic block write — block 0 and sector trailers are guarded")
        outer.append(g_wr)
        self.write_row = Adw.EntryRow(title="Text to write to block 1")
        self.write_row.set_show_apply_button(True)
        self.write_row.connect("apply", self.on_write_block1)
        g_wr.add(self.write_row)

        # -------- OUTPUT ------------------------------------------------
        outlbl = Gtk.Label(label="<b>Output</b>",
                           use_markup=True, halign=Gtk.Align.START,
                           margin_top=8)
        outer.append(outlbl)
        self.tv_out = Gtk.TextView(editable=False, cursor_visible=False,
                                    monospace=True)
        self.tv_out.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        out_scroll = Gtk.ScrolledWindow(min_content_height=260)
        out_scroll.add_css_class("card")
        out_scroll.set_child(self.tv_out)
        outer.append(out_scroll)
        self.buffer = self.tv_out.get_buffer()
        self._out_scroll = out_scroll

        self.append(
            "Ready. stnfc binary: " + STNFC + "\n"
            "Tap an action above. The phone needs to be unlocked and a\n"
            "compatible NFC tag (or another NFC device) near the upper-\n"
            "center of the back during read/clone/emulate operations.\n"
        )

    # ------ widget helpers ---------------------------------------------

    def _add_action(self, group, title, subtitle, args):
        row = Adw.ActionRow(title=title, subtitle=subtitle, activatable=True)
        row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        row.connect("activated", lambda *_: self.run(args))
        group.add(row)
        return row

    def append(self, text):
        end = self.buffer.get_end_iter()
        self.buffer.insert(end, text)
        adj = self._out_scroll.get_vadjustment()
        # Defer scroll until layout settles so it actually moves.
        GLib.idle_add(lambda: adj.set_value(adj.get_upper()) or False)

    # ------ subprocess driver ------------------------------------------

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
            rc = -1
            try:
                rc = self.proc.get_exit_status() if self.proc else -1
            except Exception:
                pass
            self.append("[stnfc exit " + str(rc) + "]\n")
            self.proc = None
            self.stop_btn.set_sensitive(False)
            return
        self.append(line + "\n")
        self._read_next(stream)

    # ------ actions ----------------------------------------------------

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
