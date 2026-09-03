"""Byte/action tracer for the LDN HOSTING path - answers "what exactly went over the air?".

attach(network, tracer, log) monkeypatches a live `ldn.APNetwork` INSTANCE (our code; no fork of the
ldn package) so every hosting-relevant action is hex-logged to a JSONL trace file:

    advert        the encoded LDN advertisement action frame (logged once + on every change, i.e.
                  whenever the advert nonce bumps: application_data/accept-policy/participant change)
    beacon_appdata  our raw application_data (the RFU beacon) for offline field-by-field comparison
    auth_req      each authentication request custom-frame (source MAC + raw bytes) - the A-press
    auth_resp     our authentication response (status code + bytes)
    join / leave  participant registration events (index, ip, mac, name)
    dataframe_in  data frames the monitor vif accepted for the TAP (first N + a running count)
    dataframe_out data frames we transmit via the monitor vif (first N + count)
    udp_in/out    the :12345 Pia datagrams over the TAP (wired via HostTransport, not the patch)

Instance-level patching works because the library's nursery loops (`_send_advertisements`,
`_receive_data_frames`, `_process_events`) resolve `self._send_advertisement` etc. per call, so
rebinding the attribute on the instance takes effect immediately - and only for this network object.
Every wrapper is defensive: a tracer bug must never break hosting, so failures degrade to a log line.

Records mirror the existing --capture conventions: JSON per line, {"rec": "trace", "kind": ...,
"ts": <unix float>, "hex"/fields...}.
"""

import json
import time

DATAFRAME_HEX_LIMIT = 20        # hex-dump the first N data frames each way; count the rest


class Tracer:
    """Append-only JSONL trace writer (one JSON object per line, flushed per record so a crash or
    Ctrl-C never loses the tail)."""

    def __init__(self, path, log=print):
        self.path = path
        self.log = log
        self._f = open(path, "a", buffering=1)
        self.counts = {}

    def write(self, kind, **fields):
        rec = {"rec": "trace", "kind": kind, "ts": round(time.time(), 6)}
        rec.update(fields)
        try:
            self._f.write(json.dumps(rec) + "\n")
        except (OSError, TypeError, ValueError) as e:       # pragma: no cover - never break hosting
            self.log(f"[trace] write failed ({kind}): {e}")
        self.counts[kind] = self.counts.get(kind, 0) + 1

    def close(self):
        try:
            if self.counts:
                self.write("summary", counts=dict(self.counts))
            self._f.close()
        except OSError:                                     # pragma: no cover
            pass


def _hex(b):
    return bytes(b).hex()


def attach(network, tracer, log=print):
    """Monkeypatch a live ldn.APNetwork instance so its hosting actions stream into `tracer`.
    Safe to call once per network object, right after ldn.create_network yields it."""

    # -- advertisement TX: log the encoded action frame once + on every nonce change --------------
    orig_send_advert = network._send_advertisement
    state = {"last_nonce": None}

    async def send_advertisement():
        try:
            nonce = bytes(network._network.nonce)
            if nonce != state["last_nonce"]:
                state["last_nonce"] = nonce
                frame = network._network.build_advertisement(network._key_derivation)
                tracer.write("advert", nonce=_hex(nonce), hex=_hex(frame.encode()))
                tracer.write("beacon_appdata", hex=_hex(network._network.application_data or b""))
                log(f"[trace] advertisement updated (nonce {nonce.hex()}, "
                    f"{len(network._network.application_data or b'')}B app_data)")
        except Exception as e:                              # noqa: BLE001 - tracing must not break TX
            log(f"[trace] advert hook error: {e}")
        return await orig_send_advert()

    network._send_advertisement = send_advertisement

    # -- authentication: the console's A-press arrives here as a custom frame ---------------------
    orig_auth = network._process_authentication_event

    async def process_authentication_event(event):
        try:
            tracer.write("auth_req", mac=str(event.address), hex=_hex(event.data))
            log(f"[trace] AUTH REQUEST from {event.address} ({len(event.data)}B)")
        except Exception as e:                              # noqa: BLE001
            log(f"[trace] auth-req hook error: {e}")
        response = await orig_auth(event)
        try:
            tracer.write("auth_resp", status=response.status_code, hex=_hex(response.encode()))
            log(f"[trace] AUTH RESPONSE status={response.status_code}")
        except Exception as e:                              # noqa: BLE001
            log(f"[trace] auth-resp hook error: {e}")
        return response

    network._process_authentication_event = process_authentication_event

    # -- participant registration (the JoinEvent source) ------------------------------------------
    orig_register = network._register_participant

    async def register_participant(address, name, app_version, platform):
        try:
            tracer.write("join", mac=str(address), name=bytes(name).hex(),
                         app_version=app_version, platform=platform)
        except Exception as e:                              # noqa: BLE001
            log(f"[trace] join hook error: {e}")
        return await orig_register(address, name, app_version, platform)

    network._register_participant = register_participant

    # -- data plane: monitor vif <-> TAP ----------------------------------------------------------
    orig_data_in = network._process_data_frame
    orig_data_out = network._send_data_frame

    async def process_data_frame(frame):
        try:
            n = tracer.counts.get("dataframe_in", 0)
            if n < DATAFRAME_HEX_LIMIT:
                tracer.write("dataframe_in", src=str(frame.source), dst=str(frame.target),
                             protected=bool(frame.protected), hex=_hex(frame.payload))
            else:
                tracer.counts["dataframe_in"] = n + 1      # count silently past the limit
        except Exception as e:                              # noqa: BLE001
            log(f"[trace] dataframe-in hook error: {e}")
        return await orig_data_in(frame)

    async def send_data_frame(data, target=None):
        try:
            n = tracer.counts.get("dataframe_out", 0)
            if n < DATAFRAME_HEX_LIMIT:
                fields = {"hex": _hex(data)}
                if target is not None:
                    fields["dst"] = str(target)
                tracer.write("dataframe_out", **fields)
            else:
                tracer.counts["dataframe_out"] = n + 1
        except Exception as e:                              # noqa: BLE001
            log(f"[trace] dataframe-out hook error: {e}")
        return await orig_data_out(data, target)

    network._process_data_frame = process_data_frame
    network._send_data_frame = send_data_frame

    log(f"[trace] attached to APNetwork -> {tracer.path}")
    return network
