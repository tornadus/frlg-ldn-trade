from types import SimpleNamespace

from frlgsim.trade_runtime import parse_slots, received_paths


def test_parse_slots_accepts_empty_and_valid_lists():
    assert parse_slots("", 2, 3) is None
    assert parse_slots("0,2", 2, 3) == [0, 2]


def test_parse_slots_rejects_invalid_lists():
    invalid = ("a", "0", "0,0", "0,3")
    for spec in invalid:
        try:
            parse_slots(spec, 2, 3)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid slot specification accepted: {spec!r}")


def test_received_paths_preserve_single_output_and_name_multiple_outputs():
    mons = [
        SimpleNamespace(species=1, species_name="Bulbasaur"),
        SimpleNamespace(species=122, species_name="Mr. Mime"),
    ]
    assert received_paths(mons[:1], "received.pk3", "pk3", 1) == ["received.pk3"]
    assert received_paths(mons, "received.pk3", "ek3", 2) == [
        "received_trade1_Bulbasaur.ek3",
        "received_trade2_MrMime.ek3",
    ]
