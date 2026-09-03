"""Offline ownership and CLI regressions for the production host runtime."""

from types import SimpleNamespace
from contextlib import contextmanager
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import frlgtrade_host
from frlgsim import config
from frlgsim.config import DEFAULT_TRAINER
from frlgsim.host_app import HostApplication


def _config(**changes):
    plan_values = dict(
        party_paths=("dummy.pk3", "Lola.pk3"),
        trade_slot=1,
        offered_slots=(1,),
        trust_pia=True,
    )
    ldn_values = {}
    option_values = {}
    for key, value in changes.items():
        if key in config.LdnConfig.__dataclass_fields__:
            ldn_values[key] = value
        elif key in config.HostOptions.__dataclass_fields__:
            option_values[key] = value
        else:
            plan_values[key] = value
    return config.TradeRunConfig(
        DEFAULT_TRAINER, config.TradePlan(**plan_values),
        config.LdnConfig(**ldn_values), config.HostOptions(**option_values))


@contextmanager
def _raises(exception_type, message):
    try:
        yield
    except exception_type as exc:
        assert message in str(exc), (message, str(exc))
    else:
        raise AssertionError(f"expected {exception_type.__name__}: {message}")


def test_host_run_config_rejects_invalid_values():
    cases = [
        ({"party_paths": ()}, "party"),
        ({"party_paths": ("a",), "trades": 2, "offered_slots": (0, 0),
          "trade_slot": 0}, "trades"),
        ({"offered_slots": ()}, "one slot per trade"),
        ({"trades": 2, "offered_slots": (0, 0)}, "distinct"),
        ({"offered_slots": (2,)}, "configured party"),
        ({"trade_slot": 2}, "trade_slot"),
        ({"output_size": 81}, "output_size"),
        ({"output_format": "bin"}, "output_format"),
        ({"anim_delay": -1}, "anim_delay"),
        ({"password": "abcd"}, "password"),
        ({"channel": 15}, "channel"),
        ({"max_participants": 1}, "max_participants"),
        ({"local_comm_id": 1 << 64}, "local_comm_id"),
        ({"scene_id": 1 << 16}, "scene_id"),
    ]
    for change, message in cases:
        with _raises(ValueError, message):
            _config(**change)


def test_host_cli_exposes_supported_options_and_removes_development_options():
    parser = frlgtrade_host.build_parser()
    exposed = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    assert {
        "--out", "--out-size", "--out-format", "--slot", "--slots",
        "--trades", "--anim-delay", "--trust-pia", "--no-trust-pia",
        "--verbose", "--live", "--password", "--phy", "--keys",
        "--comm-id", "--capture", "--channel", "--scene",
        "--max-participants", "--skip-preflight", "--skip-encryption",
        "--native-nonce-sequence", "--session-response-first",
        "--ot", "--version", "--id",
    } <= exposed
    assert {
        "--self-id", "--decline",
        "--refuse-illegit", "--compress", "--connect-id",
        "--parent-pid", "--replay",
    }.isdisjoint(exposed)


def test_host_cli_applies_shared_identity_overrides():
    parser = frlgtrade_host.build_parser()
    args = parser.parse_args([
        "--live", "--ot", "Red", "--version", "firered",
        "--id=12345:34567", "one.pk3", "two.pk3",
    ])
    run = frlgtrade_host.build_run_config(parser, args)
    assert (run.profile.name, run.profile.version) == ("Red", "firered")
    assert (run.profile.tid, run.profile.sid) == (12345, 34567)
    assert run.profile.trainer_id == (34567 << 16) | 12345


class _Log(list):
    def __call__(self, *parts):
        self.append(" ".join(str(part) for part in parts))

    def info(self, *parts):
        self(*parts)


class _Network:
    def __init__(self, participants=()):
        self.participants = list(participants)
        self.started = 0
        self.stopped = 0
        self.sent = []
        self.waits = 0
        self.on_wait = None

    def start(self, preflight=True):
        self.started += 1
        self.preflight = preflight
        return self

    def stop(self):
        self.stopped += 1

    def recv(self):
        return []

    def send(self, data, destination):
        self.sent.append((data, destination))

    def wait_readable(self, timeout):
        self.waits += 1
        if self.on_wait is not None:
            self.on_wait(self)


class _Injector:
    def __init__(self, start_error=None, runtime_error=None):
        self.start_error = start_error
        self.error = runtime_error
        self.started = 0
        self.stopped = 0

    def start(self):
        self.started += 1
        if self.start_error is not None:
            raise self.start_error
        return self

    def stop(self):
        self.stopped += 1


class _Peer:
    def __init__(self, session, network, tick_action=None):
        self.session = session
        self.network = network
        self.tick_action = tick_action
        self.joined = 0
        self.ticks = 0

    def on_participant_joined(self):
        self.joined += 1

    def receive(self, datagram, src_ip):
        return []

    def drain(self):
        return []

    def tick(self, now):
        self.ticks += 1
        if self.tick_action is not None:
            self.tick_action(self)
        return []

    def next_deadline(self, now, default):
        return default


def _session():
    trade = SimpleNamespace(
        state="test", commits=0, received_mons=[], established=False,
        close_confirmed=False, done=False)
    rfu = SimpleNamespace(host_session_id=b"\x12\x34", ni_complete=False)
    result = SimpleNamespace(trade=trade, rfu=rfu, leave_calls=0)

    def on_ldn_leave():
        result.leave_calls += 1

    result.on_ldn_leave = on_ldn_leave
    return result


class _RuntimeApplication(HostApplication):
    def __init__(self, network, injector, session, peer, *, log=None):
        super().__init__(
            _config(), log=log if log is not None else _Log(),
            injector_factory=lambda **unused: injector)
        self._test_network = network
        self._test_session = session
        self._test_peer = peer

    def _build_components(self):
        self.network = self._test_network
        self.session = self._test_session
        self.peer = self._test_peer
        self._last_trade_state = self.session.trade.state
        return DEFAULT_TRAINER.to_link_player()

    def _log_identity(self, link_player):
        pass


def test_runtime_starts_joins_and_cleans_up_after_normal_leave():
    network = _Network([("switch",)])
    injector = _Injector()
    session = _session()

    def leave_after_first_tick(peer):
        peer.network.participants.clear()

    peer = _Peer(session, network, leave_after_first_tick)
    app = _RuntimeApplication(network, injector, session, peer)
    assert app.run() is True
    assert peer.joined == 1
    assert session.leave_calls == 1
    assert (network.started, network.stopped) == (1, 1)
    assert (injector.started, injector.stopped) == (1, 1)


def test_runtime_keeps_ticking_without_participant_through_close_grace():
    network = _Network([("switch",)])
    injector = _Injector()
    session = _session()

    def complete_grace(peer):
        if peer.ticks == 1:
            session.trade.close_confirmed = True
            peer.network.participants.clear()
        elif peer.ticks == 4:
            session.trade.done = True

    peer = _Peer(session, network, complete_grace)
    log = _Log()
    app = _RuntimeApplication(network, injector, session, peer, log=log)
    assert app.run() is True
    assert peer.ticks == 4
    assert session.leave_calls == 0
    assert any("15-second host grace period" in line for line in log)
    assert network.stopped == injector.stopped == 1


def test_runtime_interruption_still_cleans_up():
    network = _Network()
    network.on_wait = lambda unused: (_ for _ in ()).throw(KeyboardInterrupt())
    injector = _Injector()
    session = _session()
    peer = _Peer(session, network)
    app = _RuntimeApplication(network, injector, session, peer)
    assert app.run() is False
    assert network.stopped == injector.stopped == 1


def test_injector_failure_stops_both_injector_and_network():
    for failure_phase in ("start", "runtime"):
        error = RuntimeError("injector failed")
        injector = _Injector(
            start_error=error if failure_phase == "start" else None,
            runtime_error=error if failure_phase == "runtime" else None)
        network = _Network()
        session = _session()
        peer = _Peer(session, network)
        app = _RuntimeApplication(network, injector, session, peer)
        with _raises(RuntimeError, "injector"):
            app.run()
        assert network.stopped == injector.stopped == 1


def test_component_construction_failure_closes_created_resources():
    tracer = SimpleNamespace(closed=0, counts={})
    tracer.close = lambda: setattr(tracer, "closed", tracer.closed + 1)
    network = _Network()
    injector = _Injector()
    session = _session()
    peer = _Peer(session, network)

    class BrokenApplication(_RuntimeApplication):
        def _build_components(self):
            self.network = network
            self.tracer = tracer
            raise RuntimeError("construction failed")

    app = BrokenApplication(network, injector, session, peer)
    with _raises(RuntimeError, "construction"):
        app.run()
    assert network.stopped == 1
    assert tracer.closed == 1
    assert injector.stopped == 0


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("host application runtime tests: OK")
