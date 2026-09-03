"""Offline end-to-end checks for the leader-side trade-room engine.

The peer below is intentionally small: it supplies the exact blocks/opcodes a right-seat FireRed
child owns, while all framing uses the real RFU and block implementations.  This catches leader /
follower ownership inversions and ordering errors without pretending to validate Pia timing.
"""

import os
import sys
from dataclasses import FrozenInstanceError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frlgsim import block, config, linkplayer, mon, rfu, trade
from frlgsim.host_session import HostSession
from frlgsim.host_trade import (
    CLOSE_RETRY_FRAMES, H_ANIM, H_CANCEL, H_DONE, H_EXIT, H_LEAVE_MENU, H_PARTY,
    H_SAVE, H_SELECT,
    ENTRY_FINAL_STANDBY_QUIET_FRAMES, FINAL_MENU_READY_FRAMES, PARTY_LINK_SETTLE_FRAMES,
    POST_CANCEL_EXIT_WAIT_FRAMES, POST_CLIENT_CLOSE_GRACE_FRAMES,
    SAVE_BARRIER_ROUNDS, SAVE_FINAL_STANDBY_QUIET_FRAMES,
    STARTUP_STANDBY_ECHO_FRAMES, HostTradeEngine, HostTradeTiming,
)


def _mon(marker):
    # Wire-validity is not relevant to this FSM test; distinct raw structs make swaps unambiguous.
    return mon.Mon(bytes([marker & 0xFF]) + b"\x00" * 99)


def _child_block(host, data, owner=1):
    """Stream one child block through the real BlockSender + rolling-tag serializer."""
    sender = block.BlockSender(data, owner=owner, trust_pia=True)
    slots = rfu.SlotBuilder()
    guard = 0
    while not sender.done:
        host.feed_child_slot(slots.build(sender.tick(None)))
        guard += 1
        assert guard < 100


def test_host_trade_timing_defaults_are_compatible_and_immutable():
    timing = HostTradeTiming()
    assert timing.save_barrier_rounds == SAVE_BARRIER_ROUNDS
    assert timing.save_final_standby_quiet_frames == SAVE_FINAL_STANDBY_QUIET_FRAMES
    assert timing.party_link_settle_frames == PARTY_LINK_SETTLE_FRAMES
    assert timing.startup_standby_echo_frames == STARTUP_STANDBY_ECHO_FRAMES
    assert timing.entry_final_standby_quiet_frames == ENTRY_FINAL_STANDBY_QUIET_FRAMES
    assert timing.final_menu_ready_frames == FINAL_MENU_READY_FRAMES
    assert timing.post_cancel_exit_wait_frames == POST_CANCEL_EXIT_WAIT_FRAMES
    assert timing.post_client_close_grace_frames == POST_CLIENT_CLOSE_GRACE_FRAMES
    assert timing.close_retry_frames == CLOSE_RETRY_FRAMES
    try:
        timing.close_retry_frames = 1
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("HostTradeTiming must be immutable")


def test_host_trade_engine_uses_supplied_timing():
    timing = HostTradeTiming(final_menu_ready_frames=2)
    h = HostTradeEngine([_mon(1)], timing=timing)
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h.round = h.trades
    h._finish_party_exchange()

    assert h.timing is timing
    h.tick()
    assert not h._host_cancel_ready
    h.tick()
    assert h._host_cancel_ready


class ScriptedChild:
    def __init__(self, host, party, offered=(0, 1)):
        self.host = host
        self.party = list(party)
        self.offered = list(offered)
        self.round = 0
        self.lp = linkplayer.LinkPlayer(name="SWITCH", version=linkplayer.VERSION_FIRE_RED)
        self.card = linkplayer.build_trainer_card(self.lp)
        self.host_rx = block.RecvBlock()
        self._req200 = 0
        self._host_party = bytearray(600)
        self._host_party_i = 0
        self._last_host_cmd = None
        self.confirmed = 0
        self.cancel_seen = False
        self.closed = False
        self._sent_warp3 = False
        self._sent_return_standby = False

    def send_words(self, words):
        # A fresh SlotBuilder is sufficient for block/linkcmd injection here: the receiver strips the
        # rolling bits.  Dedicated rolling-tag behavior is covered by rfu tests.
        self.host.feed_child_slot(rfu.SlotBuilder().build(words))

    def send_linkcmd(self, cmd, cursor=0):
        _child_block(self.host, trade.linkcmd_block(cmd, cursor))

    def send_standby(self, count):
        self.send_words(rfu.exit_standby_words(count))

    def _on_req(self, reqtype):
        if reqtype == trade.BLOCK_REQ_SIZE_NONE:
            _child_block(self.host, linkplayer.build_block(self.lp).ljust(200, b"\x00"))
        elif reqtype == trade.BLOCK_REQ_SIZE_100:
            _child_block(self.host, self.card)
        elif reqtype == trade.BLOCK_REQ_SIZE_200:
            blocks = mon.party_blocks(mon.build_player_party(self.party))
            _child_block(self.host, blocks[self._req200])
            self._req200 += 1
        elif reqtype == trade.BLOCK_REQ_SIZE_220:
            _child_block(self.host, b"\x00" * 220)
        elif reqtype == trade.BLOCK_REQ_SIZE_40:
            _child_block(self.host, b"\x00" * 40)

    def _on_host_block(self, count, data):
        if count == trade.COUNT_LINKCMD:
            cmd = int.from_bytes(data[:2], "little")
            cursor = int.from_bytes(data[2:4], "little")
            self._last_host_cmd = cmd
            if cmd == trade.SET_MONS_TO_TRADE:
                self.host_cursor = cursor
                self.send_linkcmd(trade.INIT_BLOCK)
            elif cmd == trade.START_TRADE:
                self.send_linkcmd(trade.READY_FINISH_TRADE)
            elif cmd == trade.CONFIRM_FINISH_TRADE:
                # Mirror TradeMons locally before the next BufferTradeParties exchange.
                offered = self.offered[self.round]
                off = self.host_cursor * 100
                self.party[offered] = mon.Mon(bytes(self._host_party[off:off + 100]))
                self.round += 1
                self.confirmed += 1
                self._req200 = 0
                self._host_party = bytearray(600)
                self._host_party_i = 0
                # Completed native capture: six consecutive child-initiated save rounds.
                base = 5 + (self.round - 1) * 6
                for n in range(base, base + 6):
                    self.send_standby(n)
            elif cmd == trade.BOTH_CANCEL_TRADE:
                self.cancel_seen = True
                self.send_standby(20)
            return
        if count == trade.COUNT_TRAINER_CARD:
            self.send_standby(1)
            return
        if count == trade.COUNT_PARTY:
            lp, ok = linkplayer.parse_block(data)
            if ok:
                return
            if self._host_party_i < 3:
                i = self._host_party_i
                self._host_party[i * 200:(i + 1) * 200] = data[:200]
                self._host_party_i += 1

    def consume_host_words(self, words):
        slot = rfu.serialize(words)
        rec = rfu.parse_slot(slot)
        if rec is None:
            self.host.feed_child_slot(rfu.idle_slot())
            return
        if rec["op"] == rfu.SEND_BLOCK_REQ:
            self._on_req(rec["reqtype"])
        elif rec["op"] == rfu.SEND_BLOCK_INIT:
            self.host_rx.on_init(rec["count"], rec.get("owner_raw"))
        elif rec["op"] == rfu.SEND_BLOCK:
            was_done = self.host_rx.done
            self.host_rx.on_block(rec["index"], rec["frag"])
            if self.host_rx.done and not was_done:
                data, count = self.host_rx.data(), self.host_rx.count
                self.host_rx.consume()
                self._on_host_block(count, data)
        elif rec["op"] == rfu.SEND_HELD_KEYS:
            key = rec["keycode"] & 0xFF
            if key == 0x16:
                self.send_words(rfu.held_keys_words(0x16))
                self.send_standby(2)
            elif key == 0x17:
                self.send_words(rfu.held_keys_words(0x17))
        elif rec["op"] == rfu.READY_EXIT_STANDBY:
            count = rec["count"]
            # Counts 0/1 are the host echoing an already-sent child barrier.  Count 2 completion
            # advances the child to the final post-seat round (count 3).
            if count == 2 and not self._sent_warp3:
                self._sent_warp3 = True
                self.send_standby(3)
            elif (self.cancel_seen and not self._sent_return_standby
                  and count >= 20):
                self._sent_return_standby = True
                self.send_standby((count + 1) & 0xFFFF)
        elif rec["op"] == rfu.READY_CLOSE_LINK:
            if not self.closed:
                self.closed = True
                self.send_words(rfu.close_link_words(rec["count"]))

    def maybe_select(self):
        if self.host.state == H_SELECT and self.confirmed < self.host.trades:
            self.send_linkcmd(trade.READY_TO_TRADE, self.offered[self.round])
        elif (self.host.state == H_LEAVE_MENU and self.host._host_cancel_ready
              and not self.cancel_seen and not self.host._child_cancel_requested):
            self.send_linkcmd(trade.REQUEST_CANCEL)


def test_two_trades_then_graceful_cancel_and_close():
    host_original = [_mon(0x11), _mon(0x12)]
    child_original = [_mon(0x21), _mon(0x22)]
    h = HostTradeEngine(host_original, trades=2, offered_slots=[0, 1], anim_delay=1)
    c = ScriptedChild(h, child_original)

    # LinkPlayer completes before the child initiates warp standby count 0.
    sent_warp0 = False
    for _ in range(4000):
        c.consume_host_words(h.tick())
        if h.established and not sent_warp0:
            sent_warp0 = True
            c.send_standby(0)
        c.maybe_select()
        if h.disconnect_requested and c.closed:
            h.mark_disconnect_sent()
            break
    else:
        raise AssertionError(f"leader did not finish: state={h.state}, trace={h.trace[-20:]}")

    assert h.commits == 2
    assert [m.raw for m in h.received_mons] == [child_original[0].raw, child_original[1].raw]
    assert [m.raw for m in h.party] == [child_original[0].raw, child_original[1].raw]
    assert c.confirmed == 2
    assert c.cancel_seen and c.closed and h.disconnect_requested and h.done and h.state == H_DONE

    child_cmds = [x[1] for x in h.trace if x[0] == "child_linkcmd"]
    assert child_cmds == [
        "READY_TO_TRADE", "INIT_BLOCK", "READY_FINISH_TRADE",
        "READY_TO_TRADE", "INIT_BLOCK", "READY_FINISH_TRADE",
        "REQUEST_CANCEL",
    ]
    queued = [x[1] for x in h.trace if x[0] == "queue_block"]
    assert "host:link_player_menu" not in queued
    assert queued.count("SET_MONS_TO_TRADE") == 2
    assert queued.count("START_TRADE") == 2
    assert queued.count("CONFIRM_FINISH_TRADE") == 2
    assert queued[-1] == "BOTH_CANCEL_TRADE"
    assert any(x[0] == "mail_wait_idle" for x in h.trace)
    assert any(x[0] == "ribbons_wait_idle" for x in h.trace)


def test_final_menu_waits_for_two_sided_native_cancel_decision():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h.round = h.trades
    h._finish_party_exchange()

    assert h.state == H_LEAVE_MENU
    for _ in range(FINAL_MENU_READY_FRAMES):
        h.tick()
    assert h.state == H_LEAVE_MENU
    assert h._host_cancel_ready
    assert not any(x[:2] == ("queue_block", "BOTH_CANCEL_TRADE") for x in h.trace)

    h._on_child_linkcmd(trade.REQUEST_CANCEL, 0)
    assert h.state == H_CANCEL
    queued = [x[1] for x in h.trace if x[0] == "queue_block"]
    assert queued[-1:] == ["BOTH_CANCEL_TRADE"]


def test_early_child_cancel_is_latched_until_five_second_menu_wait():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h.round = h.trades
    h._finish_party_exchange()

    h._on_child_linkcmd(trade.REQUEST_CANCEL, 0)
    assert h.state == H_LEAVE_MENU
    assert h._child_cancel_requested and not h._host_cancel_ready
    for _ in range(FINAL_MENU_READY_FRAMES - 1):
        h.tick()
    assert h.state == H_LEAVE_MENU
    h.tick()
    assert h.state == H_CANCEL


def test_extra_trade_selection_is_declined_without_false_exit():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h.round = h.trades
    h._finish_party_exchange()

    h._on_child_linkcmd(trade.READY_TO_TRADE, 0)
    assert h.state == H_LEAVE_MENU
    assert not h._child_cancel_requested
    queued = [x[1] for x in h.trace if x[0] == "queue_block"]
    assert queued[-1:] == ["PLAYER_CANCEL_TRADE"]


def test_leader_never_advances_without_child_ack_opcode():
    h = HostTradeEngine([_mon(1), _mon(2)], anim_delay=0)
    # Directly exercise the leader-only decision boundary: selecting queues SET_MONS, but START is
    # forbidden until the child supplies INIT_BLOCK.
    h._set_state(H_SELECT)
    h._on_child_linkcmd(trade.READY_TO_TRADE, 0)
    assert h.state != H_ANIM
    for _ in range(20):
        h.tick()
    assert h.state != H_ANIM
    h._on_child_linkcmd(trade.INIT_BLOCK, 0)
    assert h.state == H_ANIM


def test_entry_route_matches_native_and_exit_key_is_one_shot():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None

    h._set_state("H_ENTRY_CARD")
    h._expected = "warp1"
    h._on_child_standby(1)
    assert rfu.parse_slot(rfu.serialize(h.tick()))["op"] == rfu.READY_EXIT_STANDBY
    for _ in range(STARTUP_STANDBY_ECHO_FRAMES - 1):
        assert rfu.parse_slot(rfu.serialize(h.tick()))["op"] == rfu.READY_EXIT_STANDBY

    held = [rfu.parse_slot(rfu.serialize(h.tick()))["keycode"] for _ in range(168)]
    lows = [value & 0xFF for value in held]
    assert lows == (
        [0x11] * 43 + [0x13] * 9 + [0x11] * 4 + [0x13] * 14
        + [0x11] * 31 + [0x14] * 5 + [0x11] * 12 + [0x13] * 17
        + [0x11] * 25 + [0x16] + [0x11] * 7)
    assert [(value >> 8) & 0xFF for value in held] == list(range(1, 169))
    assert rfu.serialize(h.tick()) == rfu.idle_slot()

    h.feed_child_slot(rfu.SlotBuilder().build(rfu.held_keys_words(0x16)))
    h._on_child_standby(2)
    h._on_child_standby(3)
    assert h.state == "H_ENTRY_SEAT"
    for _ in range(ENTRY_FINAL_STANDBY_QUIET_FRAMES - 1):
        h.feed_child_slot(rfu.idle_slot())
    assert h.state == "H_ENTRY_SEAT"
    # A native >60-frame count-3 resend proves the child has not accepted our echo yet and resets
    # the completion observation window.
    h._on_child_standby(3)
    for _ in range(ENTRY_FINAL_STANDBY_QUIET_FRAMES - 1):
        h.feed_child_slot(rfu.idle_slot())
    assert h.state == "H_ENTRY_SEAT"
    h.feed_child_slot(rfu.idle_slot())
    assert h.state == H_PARTY

    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h._set_state("H_CANCEL")
    h._on_child_standby(20)
    assert rfu.parse_slot(rfu.serialize(h.tick()))["op"] == rfu.READY_EXIT_STANDBY
    h._on_child_standby(21)
    for _ in range(POST_CANCEL_EXIT_WAIT_FRAMES - 1):
        h.tick()
    assert h.state == "H_RETURN_FIELD"
    exit_words = h.tick()
    assert rfu.parse_slot(rfu.serialize(exit_words))["keycode"] & 0xFF == 0x17
    # Drain the queued barrier echoes before the EXIT_ROOM held-key plan.
    while h._words:
        h.tick()
    assert rfu.parse_slot(rfu.serialize(h.tick()))["keycode"] & 0xFF == 0x11
    h.feed_child_slot(rfu.SlotBuilder().build(rfu.held_keys_words(0x17)))
    assert not h._held_plan and h._held_steady is None

    # If the Switch exits first during the five-second delay, Linux mirrors EXIT_ROOM once and
    # proceeds to READY_CLOSE_LINK without waiting for the timer.
    h._words.clear()
    h._set_state("H_RETURN_FIELD")
    h._room_exit_wait = POST_CANCEL_EXIT_WAIT_FRAMES
    h.feed_child_slot(rfu.SlotBuilder().build(rfu.held_keys_words(0x17)))
    assert h.state == H_EXIT
    assert rfu.parse_slot(rfu.serialize(h.tick()))["keycode"] & 0xFF == 0x17
    assert h.state == "H_CLOSE"


def test_child_close_confirmation_keeps_peer_traffic_alive_for_fifteen_seconds():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h._set_state(H_EXIT)
    h._child_exit_seen = True
    h._complete_room_exit()

    close = rfu.SlotBuilder().build(rfu.close_link_words(21))
    h.feed_child_slot(close)
    assert h._close_confirmed
    assert not h.disconnect_requested
    assert h._close_grace_wait == POST_CLIENT_CLOSE_GRACE_FRAMES

    # A repeated confirmation must not restart the grace period.
    h.tick()
    remaining = h._close_grace_wait
    h.feed_child_slot(close)
    assert h._close_grace_wait == remaining

    for _ in range(remaining - 1):
        h.tick()
        assert not h.disconnect_requested
    h.tick()
    assert h.disconnect_requested
    assert h._close_grace_wait is None
    assert any(x[0] == "close_grace_complete" for x in h.trace)


def test_save_chain_requires_six_consecutive_rounds():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h._set_state(H_SAVE)
    for count in (5, 5, 7, 6, 7, 8, 9):
        h._on_child_standby(count)
    assert h.state == H_SAVE
    assert h._save_rounds == 5
    assert any(x[0] == "save_standby_out_of_sequence" for x in h.trace)
    h._on_child_standby(10)
    assert h.state == H_SAVE
    for _ in range(SAVE_FINAL_STANDBY_QUIET_FRAMES - 1):
        h.feed_child_slot(rfu.idle_slot())
    assert h.state == H_SAVE
    # A repeated final standby means the child has not accepted the echo and resets the window.
    h._on_child_standby(10)
    for _ in range(SAVE_FINAL_STANDBY_QUIET_FRAMES - 1):
        h.feed_child_slot(rfu.idle_slot())
    assert h.state == H_SAVE
    h.feed_child_slot(rfu.idle_slot())
    assert h.state == H_PARTY


def test_party_pair_waits_for_link_task_idle_not_standby():
    h = HostTradeEngine([_mon(1)])
    h._words.clear()
    h._blocks.clear()
    h._sender = None
    h._set_state(H_PARTY)
    h._expected = "party:0"
    h._after_child_block(trade.COUNT_PARTY, b"\x00" * 200)

    assert h._link_waiting_idle and not h._words
    h._on_child_standby(3)
    assert h._link_waiting_idle and not h._words
    for _ in range(PARTY_LINK_SETTLE_FRAMES - 1):
        h.feed_child_slot(rfu.idle_slot())
    assert not h._words
    h.feed_child_slot(rfu.idle_slot())
    assert rfu.parse_slot(rfu.serialize(h.tick()))["op"] == rfu.SEND_BLOCK_REQ


def test_host_party_payloads_are_identical_to_client_payloads_for_1_to_6_mons():
    """Leader and follower roles must expose the same 600-byte gPlayerParty representation."""
    for party_size in range(1, 7):
        party = [_mon(i + 1) for i in range(party_size)]
        client = trade.TradeEngine(party, trade_slot=0, trust_pia=True)
        host = HostTradeEngine(party, trade_slot=0, trust_pia=True)
        expected = mon.build_player_party(party)
        assert len(expected) == 600
        assert expected[party_size * 100:] == b"\x00" * ((6 - party_size) * 100)
        assert client._party_blocks == mon.party_blocks(expected)
        for pair in range(3):
            host._words.clear()
            host._blocks.clear()
            host._party_pair = pair
            host._request_party_pair()
            payload, label = host._blocks.popleft()
            assert label == f"host:party:{pair}"
            assert payload == client._party_blocks[pair]


def test_host_identity_uses_redundant_gen3_name_terminators():
    """The host-only wire profile pads the fixed name field with EOS bytes.

    The first FF is the normal FireRed terminator; the remaining FF bytes keep
    the trade-menu partner-name renderer bounded if the bridge or a fixed-width
    copy consumes more than the first terminator.  The working follower/client
    profile deliberately retains its capture-matching zero padding.
    """
    h = HostTradeEngine([_mon(1)], link_player=linkplayer.LinkPlayer(name="EMU"))
    payload, label = h._blocks[0]
    assert label == "host:link_player"
    parsed, ok = linkplayer.parse_block(payload)
    assert ok and parsed.name == "EMU"
    assert payload[24:32] == bytes.fromhex("bfc7cfffffffffff")
    assert h.trainer_card[linkplayer.TC_OFF_PLAYER_NAME:
                          linkplayer.TC_OFF_PLAYER_NAME + 8] == \
        bytes.fromhex("bfc7cfffffffffff")
    assert linkplayer.LinkPlayer(name="EMU").pack()[8:16] == \
        bytes.fromhex("bfc7cfff00000000")


def test_empty_mail_block_matches_firered_clear_mail_struct():
    payload = trade.empty_mail_block()
    assert len(payload) == 220
    record = b"\xff" * 26 + b"\x00" * 4 + b"\x01\x00\x00\x00"
    assert len(record) == trade.MAIL_STRUCT_SIZE
    assert payload[:trade.MAIL_STRUCT_SIZE * trade.MAIL_COUNT] == record * 6
    assert payload[trade.MAIL_STRUCT_SIZE * trade.MAIL_COUNT:] == b"\x00" * 16


def test_host_session_consumes_shared_plan_and_profile():
    plan = config.TradePlan(
        party_paths=("one.pk3", "two.pk3"), trade_slot=0,
        offered_slots=(1,), trades=1, anim_delay=7, trust_pia=True)
    profile = config.profile_from_overrides(
        ot="Red", version="firered", trainer_id=(12345, 34567))
    session = HostSession([_mon(1), _mon(2)], plan=plan, profile=profile)
    assert session.trade.offered_slots == [1]
    assert session.trade.anim_delay == 7
    assert session.trade.trust_pia
    assert session.trade.lp.trainer_id == (34567 << 16) | 12345
    assert session.trade.lp.name == "Red"


if __name__ == "__main__":
    test_host_trade_timing_defaults_are_compatible_and_immutable()
    test_host_trade_engine_uses_supplied_timing()
    test_two_trades_then_graceful_cancel_and_close()
    test_final_menu_waits_for_two_sided_native_cancel_decision()
    test_early_child_cancel_is_latched_until_five_second_menu_wait()
    test_extra_trade_selection_is_declined_without_false_exit()
    test_leader_never_advances_without_child_ack_opcode()
    test_entry_route_matches_native_and_exit_key_is_one_shot()
    test_child_close_confirmation_keeps_peer_traffic_alive_for_fifteen_seconds()
    test_save_chain_requires_six_consecutive_rounds()
    test_party_pair_waits_for_link_task_idle_not_standby()
    test_host_party_payloads_are_identical_to_client_payloads_for_1_to_6_mons()
    test_host_identity_uses_redundant_gen3_name_terminators()
    test_empty_mail_block_matches_firered_clear_mail_struct()
    print("host trade engine tests: OK")
