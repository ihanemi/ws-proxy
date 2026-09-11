from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .client import _bundled_tun2socks, run
from .config import VpnConfig
from .logging_setup import configure_file_logging
from .settings import AppSettings, load_settings, save_settings
from .version import __version__


log = logging.getLogger("ws-vpn-gui")


class VpnGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events: queue.Queue[tuple[str, object | None]] = queue.Queue()
        self.core_thread: threading.Thread | None = None
        self.core_loop: asyncio.AbstractEventLoop | None = None
        self.stop_event: asyncio.Event | None = None
        self.running = False
        self.connecting = False
        self.quitting = False
        self.tray_icon = None

        try:
            settings, token = load_settings()
        except Exception as exc:
            log.warning("Could not load saved settings: %s", exc)
            settings, token = AppSettings(), ""
        self.settings = settings

        self.relay_var = tk.StringVar(value=settings.relay)
        self.token_var = tk.StringVar(value=token)
        self.dns_var = tk.StringVar(value=settings.dns)
        self.tun_name_var = tk.StringVar(value=settings.tun_name)
        self.ipv6_var = tk.BooleanVar(value=settings.ipv6)
        self.kill_switch_var = tk.BooleanVar(value=settings.kill_switch)
        self.remember_token_var = tk.BooleanVar(value=settings.remember_token)
        self.start_minimized_var = tk.BooleanVar(value=settings.start_minimized)
        self.status_var = tk.StringVar(value="Disconnected")

        self._configure_window()
        self._build_ui()
        self._start_tray()
        self.root.after(100, self._poll_events)

        if settings.start_minimized:
            self.root.after(50, self.hide_window)

    def _configure_window(self) -> None:
        self.root.title(f"WS VPN {__version__}")
        self.root.geometry("470x430")
        self.root.minsize(450, 410)
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
        try:
            ttk.Style().theme_use("vista")
        except tk.TclError:
            pass

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        title = ttk.Label(frame, text="WS VPN", font=("Segoe UI", 18, "bold"))
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Label(frame, text="Relay").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=5)
        self.relay_entry = ttk.Entry(frame, textvariable=self.relay_var)
        self.relay_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(frame, text="Token").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
        token_row = ttk.Frame(frame)
        token_row.grid(row=2, column=1, sticky="ew", pady=5)
        token_row.columnconfigure(0, weight=1)
        self.token_entry = ttk.Entry(token_row, textvariable=self.token_var, show="•")
        self.token_entry.grid(row=0, column=0, sticky="ew")
        self.show_token_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            token_row,
            text="Show",
            variable=self.show_token_var,
            command=self._toggle_token_visibility,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(frame, text="DNS").grid(row=3, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(frame, textvariable=self.dns_var).grid(row=3, column=1, sticky="ew", pady=5)

        ttk.Label(frame, text="TUN name").grid(row=4, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(frame, textvariable=self.tun_name_var).grid(row=4, column=1, sticky="ew", pady=5)

        options = ttk.LabelFrame(frame, text="Options", padding=10)
        options.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 8))
        ttk.Checkbutton(options, text="Route IPv6 through VPN", variable=self.ipv6_var).grid(
            row=0, column=0, sticky="w", padx=(0, 16), pady=3
        )
        ttk.Checkbutton(options, text="Kill switch", variable=self.kill_switch_var).grid(
            row=0, column=1, sticky="w", pady=3
        )
        ttk.Checkbutton(options, text="Remember token securely", variable=self.remember_token_var).grid(
            row=1, column=0, sticky="w", padx=(0, 16), pady=3
        )
        ttk.Checkbutton(options, text="Start minimized", variable=self.start_minimized_var).grid(
            row=1, column=1, sticky="w", pady=3
        )

        status_box = ttk.Frame(frame)
        status_box.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(10, 8))
        status_box.columnconfigure(1, weight=1)
        ttk.Label(status_box, text="Status:").grid(row=0, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=1, sticky="w", padx=(6, 0)
        )

        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        buttons.columnconfigure((0, 1, 2), weight=1)
        self.connect_button = ttk.Button(buttons, text="Connect", command=self.connect)
        self.connect_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.disconnect_button = ttk.Button(buttons, text="Disconnect", command=self.disconnect, state="disabled")
        self.disconnect_button.grid(row=0, column=1, sticky="ew", padx=5)
        self.recover_button = ttk.Button(buttons, text="Recover", command=self.recover)
        self.recover_button.grid(row=0, column=2, sticky="ew", padx=(5, 0))

        ttk.Label(
            frame,
            text="Closing the window keeps WS VPN in the system tray. Quit disconnects the VPN first.",
            foreground="#666666",
            wraplength=420,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=(18, 0))

    def _toggle_token_visibility(self) -> None:
        self.token_entry.configure(show="" if self.show_token_var.get() else "•")

    def _settings_from_form(self) -> AppSettings:
        return AppSettings(
            relay=self.relay_var.get().strip(),
            dns=self.dns_var.get().strip(),
            tun_name=self.tun_name_var.get().strip() or "wsvpn",
            ipv6=bool(self.ipv6_var.get()),
            kill_switch=bool(self.kill_switch_var.get()),
            remember_token=bool(self.remember_token_var.get()),
            start_minimized=bool(self.start_minimized_var.get()),
        )

    def _validate(self) -> tuple[AppSettings, str, VpnConfig]:
        settings = self._settings_from_form()
        token = self.token_var.get().strip()
        if not settings.relay:
            raise ValueError("Relay is required.")
        if not token:
            raise ValueError("Token is required.")
        if not settings.tun_name:
            raise ValueError("TUN name is required.")
        dns = ipaddress.ip_address(settings.dns)
        if not isinstance(dns, ipaddress.IPv4Address):
            raise ValueError("DNS must currently be an IPv4 address.")

        config = VpnConfig(relay_url=settings.relay, token=token)
        _ = (config.relay_host, config.relay_port)
        return settings, token, config

    def connect(self) -> None:
        if self.running or self.connecting:
            return
        try:
            settings, token, config = self._validate()
            save_settings(settings, token)
        except Exception as exc:
            messagebox.showerror("WS VPN", str(exc), parent=self.root)
            return

        self.settings = settings
        self.connecting = True
        self.status_var.set("Connecting…")
        self.connect_button.configure(state="disabled")
        self.disconnect_button.configure(state="normal")
        self.recover_button.configure(state="disabled")

        self.core_thread = threading.Thread(
            target=self._core_worker,
            args=(settings, config),
            name="ws-vpn-core",
            daemon=True,
        )
        self.core_thread.start()

    def _core_worker(self, settings: AppSettings, config: VpnConfig) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        stop_event = asyncio.Event()
        self.core_loop = loop
        self.stop_event = stop_event

        args = argparse.Namespace(
            tun=True,
            tun2socks=_bundled_tun2socks(),
            tun_name=settings.tun_name,
            dns=settings.dns,
            udp_timeout="2m",
            no_ipv6=not settings.ipv6,
            no_kill_switch=not settings.kill_switch,
        )
        try:
            loop.run_until_complete(
                run(
                    config,
                    args,
                    stop_event=stop_event,
                    on_ready=lambda: self.events.put(("ready", None)),
                )
            )
            self.events.put(("stopped", None))
        except Exception as exc:
            self.events.put(("error", exc))
        finally:
            self.stop_event = None
            self.core_loop = None
            loop.close()

    def disconnect(self) -> None:
        if not self.running and not self.connecting:
            return
        loop = self.core_loop
        stop_event = self.stop_event
        if loop is None or stop_event is None:
            return
        self.status_var.set("Disconnecting…")
        self.disconnect_button.configure(state="disabled")
        try:
            loop.call_soon_threadsafe(stop_event.set)
        except RuntimeError:
            pass

    def recover(self) -> None:
        if self.running or self.connecting:
            messagebox.showinfo("WS VPN", "Disconnect the VPN before recovery.", parent=self.root)
            return
        self.recover_button.configure(state="disabled")
        self.status_var.set("Recovering…")

        def worker() -> None:
            try:
                from .windows_guard import cleanup_stale_state
                cleanup_stale_state()
                self.events.put(("recovered", None))
            except Exception as exc:
                self.events.put(("recover-error", exc))

        threading.Thread(target=worker, name="ws-vpn-recovery", daemon=True).start()

    def _poll_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "ready":
                    self.connecting = False
                    self.running = True
                    self.status_var.set("Connected")
                    self.connect_button.configure(state="disabled")
                    self.disconnect_button.configure(state="normal")
                elif event == "stopped":
                    self._set_disconnected("Disconnected")
                elif event == "error":
                    self.connecting = False
                    self.running = False
                    self.connect_button.configure(state="normal")
                    self.disconnect_button.configure(state="disabled")
                    self.recover_button.configure(state="normal")
                    text = str(payload)
                    self.status_var.set("Stopped — recovery may be required")
                    messagebox.showerror("WS VPN", text, parent=self.root)
                elif event == "recovered":
                    self._set_disconnected("Recovered / Disconnected")
                elif event == "recover-error":
                    self.recover_button.configure(state="normal")
                    self.status_var.set("Recovery failed")
                    messagebox.showerror("WS VPN", str(payload), parent=self.root)
        except queue.Empty:
            pass

        if self.quitting and not self.running and not self.connecting:
            self._destroy()
            return
        self.root.after(100, self._poll_events)

    def _set_disconnected(self, status: str) -> None:
        self.connecting = False
        self.running = False
        self.status_var.set(status)
        self.connect_button.configure(state="normal")
        self.disconnect_button.configure(state="disabled")
        self.recover_button.configure(state="normal")

    def hide_window(self) -> None:
        self.root.withdraw()

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _start_tray(self) -> None:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception as exc:
            log.warning("System tray unavailable: %s", exc)
            return

        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((5, 5, 59, 59), radius=14, fill=(35, 99, 235, 255))
        draw.line((18, 22, 25, 43, 32, 27, 39, 43, 46, 22), fill=(255, 255, 255, 255), width=5)

        def show(_icon, _item) -> None:
            self.root.after(0, self.show_window)

        def toggle(_icon, _item) -> None:
            self.root.after(0, self.disconnect if (self.running or self.connecting) else self.connect)

        def quit_app(_icon, _item) -> None:
            self.root.after(0, self.quit)

        menu = pystray.Menu(
            pystray.MenuItem("Show", show, default=True),
            pystray.MenuItem(lambda _item: "Disconnect" if (self.running or self.connecting) else "Connect", toggle),
            pystray.MenuItem("Quit", quit_app),
        )
        self.tray_icon = pystray.Icon("wsvpn", image, "WS VPN", menu)
        threading.Thread(target=self.tray_icon.run, name="ws-vpn-tray", daemon=True).start()

    def quit(self) -> None:
        if self.running or self.connecting:
            if not messagebox.askyesno(
                "WS VPN",
                "Disconnect the VPN and quit?",
                parent=self.root,
            ):
                return
            self.quitting = True
            self.disconnect()
            return
        self._destroy()

    def _destroy(self) -> None:
        try:
            settings = self._settings_from_form()
            save_settings(settings, self.token_var.get().strip())
        except Exception:
            pass
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.root.destroy()


def _configure_logging() -> None:
    configure_file_logging()


def main() -> None:
    if os.name != "nt":
        raise SystemExit("The WS VPN GUI is currently Windows-only")
    _configure_logging()
    root = tk.Tk()
    VpnGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
