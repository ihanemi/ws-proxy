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


a = Analysis(
    [os.path.join(ROOT, "vpn_windows.py")],
    pathex=[ROOT],
    binaries=[
        (required["tun2socks.exe"], "."),
        (required["wintun.dll"], "."),
    ],
    datas=[],
    hiddenimports=[
        "PIL.Image",
        "PIL.ImageDraw",
        "pystray",
        "pystray._win32",
        "vpn.client",
        "vpn.config",
        "vpn.gui",
        "vpn.settings",
        "vpn.socks5",
        "vpn.udp_protocol",
        "vpn.websocket",
        "vpn.windows_guard",
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
    version=os.path.join(ROOT, "packaging", "version_info.txt"),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    uac_admin=True,
)
