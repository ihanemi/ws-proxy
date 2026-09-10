from __future__ import annotations

import base64
import ctypes
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


CONFIG_VERSION = 1
_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_ENTROPY = b"WsVpn/settings/v1"


@dataclass
class AppSettings:
    version: int = CONFIG_VERSION
    relay: str = ""
    dns: str = "1.1.1.1"
    tun_name: str = "wsvpn"
    ipv6: bool = True
    kill_switch: bool = True
    remember_token: bool = True
    start_minimized: bool = False


def config_path() -> Path:
    override = os.getenv("WS_VPN_CONFIG_PATH")
    if override:
        return Path(override)
    root = Path(os.environ.get("APPDATA", str(Path.home())))
    return root / "WsVpn" / "config.json"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob(data: bytes) -> tuple[_DATA_BLOB, object | None]:
    if not data:
        return _DATA_BLOB(0, None), None
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return _DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _blob_bytes(blob: _DATA_BLOB) -> bytes:
    if not blob.cbData or not blob.pbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def protect_token(token: str) -> str:
    if not token:
        return ""
    if os.name != "nt":
        raise RuntimeError("DPAPI token protection is only available on Windows")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _blob(token.encode("utf-8"))
    entropy_blob, entropy_buffer = _blob(_ENTROPY)
    out_blob = _DATA_BLOB()
    del in_buffer, entropy_buffer

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "WS VPN token",
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return base64.b64encode(_blob_bytes(out_blob)).decode("ascii")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def unprotect_token(value: str) -> str:
    if not value:
        return ""
    if os.name != "nt":
        raise RuntimeError("DPAPI token protection is only available on Windows")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    encrypted = base64.b64decode(value.encode("ascii"), validate=True)
    in_blob, in_buffer = _blob(encrypted)
    entropy_blob, entropy_buffer = _blob(_ENTROPY)
    out_blob = _DATA_BLOB()
    del in_buffer, entropy_buffer

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return _blob_bytes(out_blob).decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def save_settings(
    settings: AppSettings,
    token: str,
    *,
    protector: Callable[[str], str] = protect_token,
) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = asdict(settings)
    payload["version"] = CONFIG_VERSION
    payload["protected_token"] = protector(token) if settings.remember_token and token else ""

    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def load_settings(
    *,
    unprotector: Callable[[str], str] = unprotect_token,
) -> tuple[AppSettings, str]:
    path = config_path()
    if not path.exists():
        return AppSettings(), ""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if int(payload.get("version", 0)) != CONFIG_VERSION:
            return AppSettings(), ""
        settings = AppSettings(
            version=CONFIG_VERSION,
            relay=str(payload.get("relay", "")),
            dns=str(payload.get("dns", "1.1.1.1")),
            tun_name=str(payload.get("tun_name", "wsvpn")),
            ipv6=bool(payload.get("ipv6", True)),
            kill_switch=bool(payload.get("kill_switch", True)),
            remember_token=bool(payload.get("remember_token", True)),
            start_minimized=bool(payload.get("start_minimized", False)),
        )
        protected = str(payload.get("protected_token", ""))
        token = unprotector(protected) if protected and settings.remember_token else ""
        return settings, token
    except (OSError, ValueError, TypeError, json.JSONDecodeError, UnicodeError):
        return AppSettings(), ""


def clear_saved_token() -> None:
    settings, _ = load_settings(unprotector=lambda _value: "")
    save_settings(settings, "", protector=lambda _value: "")
