"""Store or remove one plugin credential without accepting secrets on argv."""

from __future__ import annotations

import argparse
import ctypes
import getpass
import re
import sys


PREFIX = "SecureCredentialBridge/"
MAX_BLOB_BYTES = 2560


def report_cli_status(message: str) -> None:
    """Write status only when running with a console (pythonw has no stdout)."""
    if sys.stdout is not None:
        print(message)


def target_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@/-]{0,127}", value):
        raise ValueError("Target must use letters, numbers, dot, underscore, dash, slash, or @.")
    return PREFIX + value


def credential_api():
    if sys.platform != "win32":
        raise RuntimeError("Windows Credential Manager is required.")
    api = ctypes.WinDLL("Advapi32", use_last_error=True)

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [("Flags", ctypes.c_uint32), ("Type", ctypes.c_uint32), ("TargetName", ctypes.c_wchar_p),
                    ("Comment", ctypes.c_wchar_p), ("LastWritten", ctypes.c_uint64), ("CredentialBlobSize", ctypes.c_uint32),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", ctypes.c_uint32),
                    ("AttributeCount", ctypes.c_uint32), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", ctypes.c_wchar_p), ("UserName", ctypes.c_wchar_p)]

    return api, CREDENTIALW


def store_secret(target: str, secret: str) -> None:
    if not target.startswith(PREFIX) or target_name(target[len(PREFIX):]) != target:
        raise ValueError("Credential target must use the plugin's dedicated namespace.")
    if not secret:
        raise ValueError("Empty credentials are not stored.")
    blob = bytearray(secret.encode("utf-16-le"))
    if len(blob) > MAX_BLOB_BYTES:
        blob[:] = b"\0" * len(blob)
        raise ValueError("Secret exceeds the Windows Credential Manager size limit.")
    api, credential_type = credential_api()
    native_blob = (ctypes.c_ubyte * len(blob)).from_buffer(blob)
    credential = credential_type()
    credential.Type = 1  # CRED_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(native_blob, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE, still scoped to this Windows account
    api.CredWriteW.argtypes = [ctypes.POINTER(credential_type), ctypes.c_uint32]
    api.CredWriteW.restype = ctypes.c_int
    try:
        if not api.CredWriteW(ctypes.byref(credential), 0):
            raise OSError(ctypes.get_last_error(), "Windows Credential Manager write failed.")
    finally:
        blob[:] = b"\0" * len(blob)
    report_cli_status(f"Stored credential reference: {target}")


def save(target: str) -> None:
    secret = getpass.getpass("Credential secret (input hidden): ")
    if getpass.getpass("Confirm secret: ") != secret:
        raise ValueError("Secrets did not match; nothing was stored.")
    store_secret(target, secret)


def delete(target: str) -> None:
    api, _ = credential_api()
    api.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    api.CredDeleteW.restype = ctypes.c_int
    if not api.CredDeleteW(target, 1, 0):
        raise OSError(ctypes.get_last_error(), "Credential could not be removed (it may not exist).")
    report_cli_status(f"Removed credential reference: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage a Secure Credential Bridge entry in Windows Credential Manager.")
    parser.add_argument("operation", choices=("set", "delete"))
    parser.add_argument("target", help="Non-secret reference name, e.g. email/primary")
    args = parser.parse_args()
    try:
        target = target_name(args.target)
        if args.operation == "set":
            save(target)
        else:
            delete(target)
    except (ValueError, RuntimeError, OSError) as error:
        print(f"Credential operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
