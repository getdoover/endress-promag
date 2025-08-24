# eh_meter_auth.py
import asyncio
import json
import time
import base64
import traceback
from typing import Any, Dict, List, Optional, Tuple

import websockets
from Crypto.Cipher import AES
from Crypto.Hash import CMAC


# ----------------------- Crypto helpers -----------------------

def _pkcs7_pad16(b: bytes) -> bytes:
    pad = 16 - (len(b) % 16)
    return b + bytes([pad]) * pad

def _kdf_blockwise(pw_utf8: bytes) -> bytes:
    """Device's simple blockwise KDF used to derive binary keys from text."""
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
    """
    What the UI sends for ACCESS_CODE_*: szAuth='none', field=<b64 CMAC( AES(nonce:password KDF), "Endress + Hauser")>
    """
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


# ----------------------- Parsing helpers -----------------------

def _payload_has_values(payload: dict) -> bool:
    main = payload.get("Main") or []
    if isinstance(main, list):
        for it in main:
            if isinstance(it, dict) and "szDescr" in it and ("szVal" in it or "szValue" in it):
                return True
    return False

def _menu_entries(payload: dict) -> List[Tuple[str, str]]:
    lst: List[Tuple[str, str, int]] = []
    menu = payload.get("Menu") or {}
    for ent in menu.get("Entries", []) or []:
        if isinstance(ent, dict):
            _id = ent.get("szID") or ent.get("ID") or ent.get("id")
            _label = ent.get("szDescr") or ent.get("szVal") or ent.get("label")
            _ul_pid = ent.get("ulPID") or 0
            if _id and _label:
                lst.append((_id, _label, _ul_pid))
    return lst

def _collect_values(node, out: Dict[str, Dict[str, Any]]):
    if isinstance(node, dict):
        if "szDescr" in node and ("szVal" in node or "szValue" in node):
            label = str(node.get("szDescr") or "").strip()
            if label:
                unit = node.get("szUnit") or node.get("szUnit2") or None
                out[label] = {"value": node.get("szVal", node.get("szValue")), "unit": unit, "id": node.get("szID"), "timestamp": time.time()}
        for v in node.values():
            _collect_values(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_values(v, out)

# ----------------------- Client -----------------------

class EHMeter:
    """
    Hardened Endress+Hauser Proline/Promag client (read-only with PIN).
    - Logs in with PIN (default "0000") using AES/CMAC
    - Recomputes OTK/resource auth per response NONCE
    - Alternates poll/get with short delays until values appear
    - Auto re-login/reconnect once if session stalls
    """

    def __init__(self, host: str, password: str = "0000", port: int = 80, swi_version: str = "411_V2_1_07", debug: bool = False):
        self.host = host
        self.port = int(port)
        self.password = password
        self.swi_version = swi_version
        self.debug = bool(debug)

        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.smk_str: Optional[str] = None
        self.session: Dict[str, Any] = {}
        self.last_payload: Optional[dict] = None

        self.values: Dict[str, Dict[str, Any]] = {}

        # timings
        self._gap = 0.15  # seconds between requests; too fast = empty Main

    # -------- public sync --------

    async def update(self):
        return await self.get_measured_values_async()

    def get_measured_values(self) -> Dict[str, Dict[str, Any]]:
        asyncio.run(self.get_measured_values_async())
        return self.values

    async def get_measured_values_async(self) -> Dict[str, Dict[str, Any]]:
        for attempt in (1, 2):
            try:
                async with self:
                    p = await self._prime_and_login()
                    p = await self._ensure_measurements_page(p)
                    self.values.update(self._extract_values(p))
                    p = await self._ensure_network_page(p)
                    self.values.update(self._extract_values(p))
                    await self._logout(p)
                    if self.values or attempt == 2:
                        return self.values
            except Exception as e:
                print("ERROR Retrieving EH Measured Values : ", e)
                if self.debug:
                    traceback.print_exc()

    # -------- async context --------

    async def __aenter__(self):
        await self._connect()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self._close()

    # -------- wire io --------

    async def _connect(self):
        url = f"ws://{self.host}:{self.port}/"
        origin = f"http://{self.host}"
        self.session.clear()
        self.last_payload = None
        self.smk_str = None
        try:
            self.ws = await websockets.connect(url, extra_headers={"Origin": origin}, max_size=None)
        except TypeError:
            try:
                self.ws = await websockets.connect(url, origin=origin, max_size=None)
            except TypeError:
                self.ws = await websockets.connect(url, max_size=None)

    async def _close(self):
        if self.ws:
            try:
                await self.ws.close()
            finally:
                self.ws = None

    async def _send(self, obj: dict) -> dict:
        assert self.ws is not None
        await self.ws.send(json.dumps(obj))
        raw = await self.ws.recv()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {}
        sess = payload.get("Session") or {}
        if sess:
            self.session.update(sess)
        self.last_payload = payload
        await asyncio.sleep(self._gap)  # pacing
        return payload

    def _decorate(self, msg: dict, *, reqtype: str = "get", ul_pid: Optional[int] = None) -> dict:
        msg.setdefault("ServletName", "servlet/main.json")
        msg.setdefault("ulPID", ul_pid or self.session.get("ulPID", 20007))
        msg.setdefault("ulAccCode", self.session.get("ulAccCode", 0))
        msg.setdefault("ReqType", reqtype)
        msg.setdefault("SWIVersion", self.session.get("SWIVersion", self.swi_version))
        msg.setdefault("BrowserID", 1)
        msg.setdefault("Status", 0)
        msg.setdefault("Time", int(time.time()))

        # Always compute using the **latest** session values
        nonce = self.session.get("ulNONCE")

        # Detect if this is the password submission step
        is_login_step = False
        pairs = msg.get("Pairs") or []
        if isinstance(pairs, list):
            for p in pairs:
                if isinstance(p, dict):
                    for k in p.keys():
                        if isinstance(k, str) and (k.startswith("ACCESS_CODE") or k == "PASSWORD_ID"):
                            is_login_step = True
                            break
                if is_login_step:
                    break

        # Set Status to match typical firmware behavior
        if reqtype == "set":
            msg["Status"] = 3
        elif reqtype == "poll":
            msg["Status"] = 0

        # Token logic aligned with HAR behavior:
        # - During login step: include ulOtkNonce and set szOtkAuthToken to "?no_pw"; do not send szResAuth
        # - After login: compute and send OTK (and szResAuth) using current session values
        if isinstance(nonce, int):
            msg["ulOtkNonce"] = int(nonce)
        if is_login_step:
            if self.smk_str and isinstance(nonce, int):
                msg["szOtkAuthToken"] = _otk_token(self.smk_str, int(self.session.get("ulAccCode", 0)), int(nonce))
                msg["szResAuth"] = _res_auth(
                    msg["ServletName"],
                    self.smk_str,
                    int(self.session.get("ulAccCode", 0)),
                    int(self.session.get("ulFilePostNonce", 0) or 0),
                )
            else:
                msg["szOtkAuthToken"] = "?no_pw"
        elif self.smk_str and isinstance(nonce, int):
            msg["szOtkAuthToken"] = _otk_token(self.smk_str, int(self.session.get("ulAccCode", 0)), int(nonce))
            # msg["szResAuth"] = _res_auth(
            #     msg["ServletName"],
            #     self.smk_str,
            #     int(self.session.get("ulAccCode", 0)),
            #     int(self.session.get("ulFilePostNonce", 0) or 0),
            # )
        elif isinstance(nonce, int) and not self.smk_str:
            # Pre-login non-SET requests often include a placeholder token
            msg["szOtkAuthToken"] = "?no_pw"
        return msg

    # -------- message builders --------

    def _msg_init_get(self) -> dict:
        return self._decorate({
            "Method": "POST",
            "ServletName": "servlet/main.json",
            "ulPID": 20007,
            "ulAccCode": 0,
            "ReqType": "get",
            "SWIVersion": self.swi_version,
            "BrowserID": 1,
            "Status": 0,
            "Time": int(time.time()),
            "Pairs": [{"szID": "header"}],
        }, reqtype="get")

    def _msg_get(self, *sections: str) -> dict:
        if not sections:
            sections = ("header", "menu", "breadcrumb", "main")
        pairs = [{"szID": sec} for sec in sections]
        return self._decorate({"ServletName": "servlet/main.json", "Pairs": pairs}, reqtype="get")

    def _msg_poll(self) -> dict:
        return self._decorate({"ServletName": "servlet/main.json"}, reqtype="poll")

    def _msg_press(self, button_id: str, ul_pid: int) -> dict:
        return self._decorate({
            "ServletName": "servlet/main.json",
            "Pairs": [{"szID": button_id}],
            "Method": "POST",
        }, reqtype="get", ul_pid=ul_pid)

    async def _logout(self, payload: dict) -> dict:
        return await self._click_menu(payload, "Logout")

    def _msg_set_password(self, access_code_id: str, *, nonce: int, enc_type: int, password: str, extra_pairs: Optional[List[Dict[str, Any]]] = None) -> dict:
        pairs = [{"ulNONCE": int(nonce)}, {"ulEncType": int(enc_type)}]
        if enc_type == 1:
            szAuth, field_val = _auth_verify_aes(nonce, password)
        else:
            szAuth, field_val = "none", password
        pairs.append({"szAuth": szAuth})
        pairs.append({access_code_id: field_val})
        if extra_pairs:
            pairs = list(extra_pairs) + pairs
        return self._decorate({
            "ServletName": "servlet/main.json",
            "Pairs": pairs,
        }, reqtype="set")

    # -------- high-level flows --------

    async def _prime_and_login(self) -> dict:
        # initial frames
        await self._send(self._msg_init_get())
        p = await self._send(self._msg_poll())
        p = await self._maybe_updates(p)

        # login if ACCESS_CODE present
        p = await self._maybe_login(p)

        entries = (p.get("Menu", {}) or {}).get("Entries", []) or []
        if not entries and self.debug:
            print("WARNING: Not logged in")
        return p

    async def _maybe_updates(self, payload: dict) -> dict:
        sess = payload.get("Session") or {}
        if any(sess.get(k, False) for k in ("menuUpdate", "breadcrumbUpdate", "mainUpdate", "headerUpdate")):
            return await self._send(self._msg_get("header", "menu", "breadcrumb", "main"))
        return payload

    async def _maybe_login(self, payload: dict) -> dict:
        access_code_id = None
        enc_type = 1
        nonce = (payload.get("Session") or {}).get("ulNONCE")
        main = payload.get("Main") or []
        if isinstance(main, list):
            for it in main:
                if isinstance(it, dict) and it.get("eType") == 11 and it.get("Items"):
                    for sub in it["Items"]:
                        if sub.get("szID", "").startswith("ACCESS_CODE"):
                            access_code_id = sub["szID"]
                            enc_type = int(sub.get("ulEncType", 1) or 1)
                            break
        if not access_code_id or nonce is None:
            return payload  # no login needed/available

        self.smk_str = _derive_smk(self.password)

        extra_pairs = [{"PASSWORD_ID": "Maintenance"}]
        p = await self._send(self._msg_set_password(
            access_code_id,
            nonce=int(nonce),
            enc_type=enc_type,
            password=self.password,
            extra_pairs=extra_pairs or None,
        ))

        return p

    async def _ensure_measurements_page(self, payload: dict) -> dict:
        nxt = await self._click_menu(payload, "Measured")
        if nxt and _payload_has_values(nxt):
            return nxt
        return payload
    
    async def _ensure_network_page(self, payload: dict) -> dict:
        nxt = await self._click_menu(payload, "Network")
        if nxt and _payload_has_values(nxt):
            return nxt
        return payload

    async def _click_menu(self, payload: dict, *keywords: str) -> Optional[dict]:
        for _id, _label, _ul_pid in _menu_entries(payload):
            if any(k.lower() in _label.lower() for k in keywords):
                request = self._msg_press(_id, _ul_pid)
                page = await self._send(request)
                return page
        return None
    
    def get_value(self, value_id: str) -> Optional[float]:
        return self.values.get(value_id, {}).get("value", None)
    
    def clear_values(self):
        self.values.clear()

    def value_update_age(self, value_id: str) -> Optional[float]:
        ts = self.values.get(value_id, {}).get("timestamp", None)
        if ts is None:
            return None
        return round(time.time() - ts, 2)

    # -------- parse & scrape --------

    def _extract_values(self, payload: dict) -> Dict[str, Dict[str, Any]]:
        vals: Dict[str, Dict[str, Any]] = {}
        _collect_values(payload, vals)
        return vals

    def _scrape_info(self, payload: dict) -> Dict[str, Any]:
        vals = self._extract_values(payload)
        return {
            "device_name": vals.get("Device name", {}).get("value"),
            "device_tag": vals.get("Device tag", {}).get("value"),
            "status": vals.get("Status signal", {}).get("value"),
            "firmware": (self.session.get("SWIVersion") or vals.get("Firmware", {}).get("value")),
        }


# ----------------------- CLI -----------------------

if __name__ == "__main__":
    meter = EHMeter("1.tcp.au.ngrok.io", password="0000", port=20779, debug=False)
    vals = meter.get_measured_values()
    print(f"Found {len(vals)} measured values")
    for k, v in vals.items():
        unit = f" {v['unit']}" if v["unit"] else ""
        print(f"{k}: {v['value']}{unit}")

    print("")
    print(f"Last update age (s): {meter.value_update_age('Totalizer value 1')}")


    ## Example Output:
    # 
    # Found 14 measured values
    # Device name: Promag 400
    # Device tag: Promag
    # Status signal: Device ok
    # Output curr. 1: 4.00 mA
    # Volume flow: 0.0000 m³/h
    # Mass flow: 0.0000 kg/min
    # Correct.vol.flow: 0.0000 Nl/h
    # Conductivity: -nan µS/cm
    # Totalizer value 1: 3481.260 m³
    # Totalizer overflow 1: 0
    # Totalizer value 2: 3481260 dm³
    # Totalizer overflow 2: 0
    # Totalizer value 3: 3481260 dm³
    # Totalizer overflow 3: 0

    # Last update age (s): 0.67