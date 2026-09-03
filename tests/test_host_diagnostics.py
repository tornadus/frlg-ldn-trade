import json
import os
import tempfile

from frlgsim import ldntrace, transport


_IW_NO_AP = """Wiphy phy0
Supported interface modes:
 * managed
 * monitor
software interface modes (can always be added):
 * monitor
"""

_IW_WITH_AP = """Wiphy phy1
Supported interface modes:
 * managed
 * AP
 * monitor
software interface modes (can always be added):
 * monitor
"""


def test_preflight_rejects_phy_without_ap_mode():
    modes, soft = transport._parse_iw_modes(_IW_NO_AP)
    assert modes == ["managed", "monitor"] and soft == ["monitor"]
    try:
        transport.preflight_host("phy0", log=lambda *parts: None, _iw_output=_IW_NO_AP)
    except RuntimeError as exc:
        assert "no AP mode" in str(exc) and "AP-capable adapter" in str(exc)
    else:
        raise AssertionError("preflight accepted a phy without AP mode")


def test_preflight_accepts_ap_capable_phy():
    assert transport.preflight_host(
        "phy1", log=lambda *parts: None, _iw_output=_IW_WITH_AP) is True


def test_tracer_writes_records_and_summary():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "trace.jsonl")
        tracer = ldntrace.Tracer(path, log=lambda *parts: None)
        tracer.write("udp_out", dst="169.254.1.255", hex="5c00")
        tracer.write("advert", nonce="00000001", hex="7f0022aa")
        tracer.close()
        with open(path, encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream]
    assert [record["kind"] for record in records] == ["udp_out", "advert", "summary"]
    assert all(record["rec"] == "trace" and "ts" in record for record in records)
    assert records[2]["counts"]["advert"] == 1
