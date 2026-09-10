# -*- mode: python ; coding: utf-8 -*-

import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(SPEC), os.pardir))
VENDOR = os.path.join(ROOT, "vendor", "windows-amd64")

required = {
    "tun2socks.exe": os.path.join(VENDOR, "tun2socks.exe"),
    "wintun.dll": os.path.join(VENDOR, "wintun.dll"),
}
for name, path in required.items():
    if not os.path.isfile(path):
        raise SystemExit(f"Missing bundled runtime: {name} ({path})")

icon_path = os.path.join(ROOT, "icon.ico")

a = Analysis(
    [os.path.join(ROOT, "vpn_windows.py")],
    pathex=[ROOT],
    binaries=[
        (required["tun2socks.exe"], "."),
        (required["wintun.dll"], "."),
    ],
    datas=[],
    hiddenimports=[
        "vpn.client",
        "vpn.config",
        "vpn.socks5",
        "vpn.udp_protocol",
        "vpn.websocket",
        "vpn.windows_tun",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WsVpn",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    icon=icon_path if os.path.isfile(icon_path) else None,
)
