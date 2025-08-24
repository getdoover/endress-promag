import argparse
import base64
import json
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import CMAC


def _pkcs7_pad16(b: bytes) -> bytes:
    pad = 16 - (len(b) % 16)
    return b + bytes([pad]) * pad


def _kdf_blockwise(pw_utf8: bytes) -> bytes:
    data = _pkcs7_pad16(pw_utf8)
    o = bytes(range(16))
    for i in range(0, len(data), 16):
        key = data[i:i + 16]
        cipher = AES.new(key, AES.MODE_ECB)
        f = cipher.encrypt(o)
        o = bytes(x ^ y for x, y in zip(o, f))
    return o


def _derive_smk(password: str) -> str:
    raw = _kdf_blockwise(f"SMK:{password}".encode("utf-8"))
    return base64.b64encode(raw).decode("ascii")


def _cmac(key_bytes: bytes, msg: bytes) -> bytes:
    c = CMAC.new(key_bytes, ciphermod=AES)
    c.update(msg)
    return c.digest()


def _auth_verify_aes(nonce: int, password: str) -> Tuple[str, str]:
    key = _kdf_blockwise(f"{nonce}:{password}".encode("utf-8"))
    token = _cmac(key, b"Endress + Hauser")
    return "none", base64.b64encode(token).decode("ascii")


def _otk_token(smk_str: str, acc_code: int, nonce: int) -> str:
    key = _kdf_blockwise(smk_str.encode("utf-8"))
    c = CMAC.new(key, ciphermod=AES)
    c.update(f"OTK:{acc_code}:{nonce}".encode("utf-8"))
    return base64.b64encode(c.digest()).decode("ascii")


def _res_auth(servlet: str, smk_str: str, acc_code: int, filepost_nonce: int = 0) -> str:
    key = _kdf_blockwise(smk_str.encode("utf-8"))
    mac = _cmac(key, f"RAK:{acc_code}:{int(filepost_nonce)}:{servlet}".encode("utf-8"))
    b64 = base64.b64encode(mac).decode("ascii")
    return b64.replace("=", "-").replace("+", "*").replace("/", "_")


def _pairs_find(pairs: List[Dict[str, Any]], key_predicate) -> Optional[Tuple[str, Any]]:
    for p in pairs or []:
        if isinstance(p, dict):
            for k, v in p.items():
                if key_predicate(k):
                    return k, v
    return None


def parse_har_messages(har: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Yield (direction, message_json) where direction is 'send' or 'receive'."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for ent in har.get("log", {}).get("entries", []) or []:
        msgs = ent.get("_webSocketMessages")
        if not msgs:
            continue
        for m in msgs:
            direction = m.get("type")
            data = m.get("data")
            if not isinstance(data, str):
                continue
            data_str = data.strip()
            if not data_str.startswith("{"):
                continue
            try:
                obj = json.loads(data_str)
            except Exception:
                continue
            out.append((str(direction or ""), obj))
    return out


def verify_har(har_path: str, password: str) -> int:
    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    messages = parse_har_messages(har)
    session: Dict[str, Any] = {}
    smk_str = _derive_smk(password)

    any_mismatch = False
    seq = 0
    for direction, obj in messages:
        if direction == "receive":
            sess = obj.get("Session") or {}
            if isinstance(sess, dict):
                session.update(sess)
            continue

        # Only verify sends
        seq += 1
        req_type = obj.get("ReqType")
        servlet = obj.get("ServletName", "servlet/main.json")
        acc = int(obj.get("ulAccCode", session.get("ulAccCode", 0)) or 0)
        otk_nonce = obj.get("ulOtkNonce", session.get("ulNONCE"))
        filepost = int(session.get("ulFilePostNonce", 0) or 0)
        pairs = obj.get("Pairs") or []

        # Compute expected tokens
        expected_otk = None
        if isinstance(otk_nonce, int):
            expected_otk = _otk_token(smk_str, acc, int(otk_nonce))
        actual_otk = obj.get("szOtkAuthToken")

        expected_res = _res_auth(servlet, smk_str, acc, filepost)
        actual_res = obj.get("szResAuth")

        # ACCESS_CODE if present
        access_entry = _pairs_find(pairs, lambda k: isinstance(k, str) and k.startswith("ACCESS_CODE"))
        ulnonce_entry = _pairs_find(pairs, lambda k: k == "ulNONCE")
        expected_access = None
        actual_access = None
        if access_entry and ulnonce_entry and isinstance(ulnonce_entry[1], int):
            _, actual_access = access_entry
            _, nonce_val = ulnonce_entry
            _, expected_access = _auth_verify_aes(int(nonce_val), password)

        # Determine statuses
        def status(expected: Optional[str], actual: Optional[str], *, placeholder_ok: bool = False) -> str:
            if actual is None:
                return "missing"
            if placeholder_ok and actual == "?no_pw":
                return "placeholder"
            if expected is None:
                return "n/a"
            return "ok" if actual == expected else "BAD"

        is_login = bool(_pairs_find(pairs, lambda k: isinstance(k, str) and (k == "PASSWORD_ID" or k.startswith("ACCESS_CODE"))))
        s_otk = status(expected_otk, actual_otk, placeholder_ok=is_login)
        s_res = status(expected_res, actual_res)
        s_acc = status(expected_access, actual_access)
        auth_status = int(session.get("ulOtkAuthStatus", 0) or 0)

        print(f"[{seq:03}] {req_type or ''} login={is_login} otk={s_otk} res={s_res} access={s_acc} ulOtkAuthStatus={auth_status}")

        if s_otk == "BAD" or s_res == "BAD" or s_acc == "BAD":
            any_mismatch = True

    return 1 if any_mismatch else 0


def main():
    ap = argparse.ArgumentParser(description="Verify E+H SWI auth tokens from a HAR")
    ap.add_argument("--har", required=True, help="Path to HAR file")
    ap.add_argument("--password", required=True, help="PIN/password used")
    args = ap.parse_args()
    rc = verify_har(args.har, args.password)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()


