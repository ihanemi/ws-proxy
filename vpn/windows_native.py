"""Small Win32 primitives; imports remain safe on non-Windows test hosts."""
from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass

MUTEX_NAME = r"Global\WsVpn.NetworkSession.v2"
QUERY = 0x1000
SYNCHRONIZE = 0x100000
TERMINATE = 0x0001


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    created: int
    path: str


def kernel32():
    if os.name != "nt":
        raise RuntimeError("Win32 operation requires Windows")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateMutexW": ([ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
        "ReleaseMutex": ([wintypes.HANDLE], wintypes.BOOL),
        "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                        ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        "GetProcessTimes": ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
        "TerminateProcess": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        "GetSystemDirectoryW": ([wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
        "LocalFree": ([ctypes.c_void_p], ctypes.c_void_p),
        "CreateDirectoryW": ([wintypes.LPCWSTR, ctypes.c_void_p], wintypes.BOOL),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(api, name)
        fn.argtypes, fn.restype = args, result
    return api


def system_executable(relative: str) -> str:
    api = kernel32()
    buffer = ctypes.create_unicode_buffer(32768)
    if not api.GetSystemDirectoryW(buffer, len(buffer)):
        raise ctypes.WinError(ctypes.get_last_error())
    return os.path.join(buffer.value, relative)


@contextmanager
def session_lock():
    api = kernel32()
    handle = api.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    owned = False
    try:
        result = api.WaitForSingleObject(handle, 0)
        if result == 258:
            raise RuntimeError("WS VPN is active in another process. Disconnect it before recovery or uninstall.")
        if result not in (0, 0x80):  # acquired or abandoned by a crashed owner
            raise ctypes.WinError(ctypes.get_last_error())
        owned = True
        yield
    finally:
        if owned:
            api.ReleaseMutex(handle)
        api.CloseHandle(handle)


def _identity(api, handle, pid: int) -> ProcessIdentity:
    times = [wintypes.FILETIME() for _ in range(4)]
    if not api.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    name = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(name))
    if not api.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    return ProcessIdentity(pid, created, name.value)


def process_identity(pid: int) -> ProcessIdentity | None:
    api = kernel32()
    handle = api.OpenProcess(QUERY | SYNCHRONIZE, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:  # process already exited
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _identity(api, handle, pid)
    finally:
        api.CloseHandle(handle)


def stop_recorded_process(expected: ProcessIdentity) -> bool:
    api = kernel32()
    handle = api.OpenProcess(QUERY | SYNCHRONIZE | TERMINATE, False, expected.pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return False
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        actual = _identity(api, handle, expected.pid)
        if actual.created != expected.created or os.path.normcase(actual.path) != os.path.normcase(expected.path):
            return False
        if api.WaitForSingleObject(handle, 0) == 0:
            return False
        # Validate and terminate using the SAME HANDLE, never a second PID lookup.
        if not api.TerminateProcess(handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if api.WaitForSingleObject(handle, 5000) != 0:
            raise RuntimeError("Recorded tun2socks process did not exit; recovery state preserved")
        return True
    finally:
        api.CloseHandle(handle)


def create_private_directory(path: str) -> None:
    """Create a directory owned by Administrators, accessible only to BA/SYSTEM.

    Existing directories are never adopted here. The caller must validate their
    owner, ACL and reparse status before reading any privileged recovery data.
    """
    api = kernel32()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    if not convert("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]
    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    try:
        if not api.CreateDirectoryW(path, ctypes.byref(attributes)) and ctypes.get_last_error() != 183:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        api.LocalFree(descriptor)


def write_private_state(path: str, payload: bytes) -> None:
    """Atomically replace privileged state with a BA-owned, protected file."""
    import uuid
    api = kernel32()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    api.WriteFile.restype = wintypes.BOOL
    api.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    api.FlushFileBuffers.restype = wintypes.BOOL
    api.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.MoveFileExW.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    if not convert("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]
    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    handle = None
    try:
        handle = api.CreateFileW(temporary, 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            handle = None
            raise ctypes.WinError(ctypes.get_last_error())
        data = ctypes.create_string_buffer(payload)
        written = wintypes.DWORD()
        if not api.WriteFile(handle, data, len(payload), ctypes.byref(written), None) or written.value != len(payload):
            raise ctypes.WinError(ctypes.get_last_error())
        if not api.FlushFileBuffers(handle):
            raise ctypes.WinError(ctypes.get_last_error())
        api.CloseHandle(handle)
        handle = None
        if not api.MoveFileExW(temporary, path, 0x1 | 0x8):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if handle is not None:
            api.CloseHandle(handle)
        api.LocalFree(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)
