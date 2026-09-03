#!/usr/bin/env python3
"""Deterministic full-stack validation of the FRLG leader implementation.

This test intentionally uses the public boundaries between all three leader
layers instead of calling their internal state transitions directly::

    HostReliableSession -> RFULeader -> HostTradeEngine

The peer is a small scripted FireRed child.  It speaks serialized Reliable
frames, emulator C/A/T/K/D frames, RFU NI and UNI, and real block/link-command
slots.  A deterministic in-memory radio drops, duplicates, and reorders DATA
in both directions.  Consequently the test covers the integration properties
that the layer-specific tests cannot: Reliable must hide those impairments
from RFU, RFU must reflect each unique child command into UNI, and the trade
engine must still finish two trades and its graceful close handshake.

It remains an offline protocol model: Pia encryption/addressing, kernel Wi-Fi
timing and Nintendo's exact implementation quirks still require a live Switch.
"""

from collections import defaultdict
from dataclasses import dataclass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frlgsim import block, gbaframe, linkplayer, mon, ni, reliable, rfu, trade
from frlgsim.host_session import HostSession
from frlgsim.host_trade import H_DONE, PARTY_LINK_SETTLE_FRAMES, HostTradeEngine
from frlgsim.rfu_leader import DISCONNECTED, UNI, RFULeader


def _mon(marker):
    return mon.Mon(bytes([marker & 0xFF]) + b"\x00" * 99)


@dataclass
class _AirPacket:
    due: int
    order: int
    direction: str
    wire: bytes


class ImpairedRadio:
    """A deterministic bidirectional datagram link.

    First transmissions of selected Reliable DATA sequence ids are dropped;
    selected ids are duplicated; and alternating delay makes later frames
    overtake earlier ones.  Retransmissions are recognized by direction+seq
    and delivered normally.  Control ACKs are never dropped so the test stays
    focused on DATA recovery rather than randomized test duration.
    """

    def __init__(self):
        self.pending = []
        self._order = 0
        self.attempts = defaultdict(int)
        self.dropped = []
        self.duplicated = []
        self.reordered = 0
        self.delivered = 0
        self.control_frames = defaultdict(int)
        self.initialized = []
        # fff3 is early child NI; fff4 is early parent NI/ACK traffic.  Both
        # peers continue emitting, creating a real selective-ACK gap.
        self.drop_once = {("child", 0xFFF3), ("host", 0xFFF4)}
        self.duplicate_once = {("child", 0xFFF2), ("host", 0xFFF2)}

    def send(self, direction, emission, now):
        wire = emission.serialize()
        frame = reliable.parse_reliable(wire)
        is_data = bool(frame.flagsA & 1)
        key = (direction, frame.seq)
        self.attempts[key] += 1
        attempt = self.attempts[key]
        if not is_data:
            self.control_frames[direction] += 1
        if is_data and (frame.flagsA & reliable.FLAGSA_INIT):
            self.initialized.append((direction, frame.seq, frame.payload))

        if is_data and key in self.drop_once and attempt == 1:
            self.dropped.append(key)
            return

        # Alternating 1/4 ms delay makes neighboring DATA frames overtake one
        # another. Reliable control frames use the short path.
        delay = 1 if not is_data or (frame.seq & 1) else 4
        if is_data and delay == 1:
            self.reordered += 1
        self._enqueue(direction, wire, now + delay)
        if is_data and key in self.duplicate_once and attempt == 1:
            self.duplicated.append(key)
            self._enqueue(direction, wire, now + delay + 1)

    def _enqueue(self, direction, wire, due):
        self._order += 1
        self.pending.append(_AirPacket(due, self._order, direction, wire))

    def deliver(self, now):
        ready = [p for p in self.pending if p.due <= now]
        self.pending = [p for p in self.pending if p.due > now]
        ready.sort(key=lambda p: (p.due, p.order))
        self.delivered += len(ready)
        return ready


class ScriptedFireRedChild:
    """Right-seat peer that reacts only to leader wire traffic."""

    def __init__(self, party, *, offered=(0, 1), trades=2):
        self.party = list(party)
        self.offered = list(offered)
        self.trades = trades
        self.rel = reliable.HostReliableSession(ack_period_ms=5,
                                                rto_bootstrap_ms=20)
        self.lp = linkplayer.LinkPlayer(name="SWITCH",
                                        version=linkplayer.VERSION_FIRE_RED)
        self.card = linkplayer.build_trainer_card(self.lp)
        self.connect_id = b"\x80\x84"
        self.ni_send = None
        self.ni_recv = ni.NIReceiver()
        self.uni_ready = False
        self.ts = 1
        self.k_seq = 1
        self._cmd_slots = []
        self._slot_builder = rfu.SlotBuilder()
        self.host_rx = block.RecvBlock()
        self._req200 = 0
        self._host_party = bytearray(600)
        self._host_party_i = 0
        self.round = 0
        self.confirmed = 0
        self.cancel_seen = False
        self.close_seen = False
        self.disconnect_seen = False
        self.accept_seen = False
        self.ni_frames_out = 0
        self.ni_frames_in = 0
        self.uni_frames_out = 0
        self.uni_frames_in = 0
        self._sent_warp3 = False
        self._sent_return_standby = False
        self._gba_pending = []
        self.ready_keys_seen = 0
        self.exit_keys_seen = 0
        self._awaiting_select = False
        self._post_ribbon_idle = 0

    def start(self, now):
        """Open the joiner stream with metadata, followed by RFU C."""
        return [
            self.rel.open(reliable.METADATA_FRAME, now),
            self.rel.send(gbaframe.build_connect(self.connect_id), now),
        ]

    def _queue_words(self, words):
        self._cmd_slots.append(self._slot_builder.build(words))

    def _queue_block(self, data):
        sender = block.BlockSender(data, owner=1, trust_pia=True)
        guard = 0
        while not sender.done:
            self._queue_words(sender.tick(None))
            guard += 1
            assert guard < 100

    def _queue_linkcmd(self, cmd, cursor=0):
        self._queue_block(trade.linkcmd_block(cmd, cursor))

    def _queue_standby(self, count):
        self._queue_words(rfu.exit_standby_words(count))

    def _on_block_request(self, reqtype):
        if reqtype == trade.BLOCK_REQ_SIZE_NONE:
            self._queue_block(linkplayer.build_block(self.lp).ljust(200, b"\x00"))
            # Child owns the first warp barrier after its LinkPlayer block.
            self._queue_standby(0)
        elif reqtype == trade.BLOCK_REQ_SIZE_100:
            self._queue_block(self.card)
        elif reqtype == trade.BLOCK_REQ_SIZE_200:
            pieces = mon.party_blocks(mon.build_player_party(self.party))
            self._queue_block(pieces[self._req200])
            self._req200 += 1
        elif reqtype == trade.BLOCK_REQ_SIZE_220:
            self._queue_block(b"\x00" * 220)
        elif reqtype == trade.BLOCK_REQ_SIZE_40:
            self._queue_block(b"\x00" * 40)
            self._awaiting_select = True
            self._post_ribbon_idle = 0

    def _on_host_block(self, count, data):
        if count == trade.COUNT_LINKCMD:
            cmd = int.from_bytes(data[:2], "little")
            cursor = int.from_bytes(data[2:4], "little")
            if cmd == trade.SET_MONS_TO_TRADE:
                self.host_cursor = cursor
                self._queue_linkcmd(trade.INIT_BLOCK)
            elif cmd == trade.START_TRADE:
                self._queue_linkcmd(trade.READY_FINISH_TRADE)
            elif cmd == trade.CONFIRM_FINISH_TRADE:
                child_slot = self.offered[self.round]
                off = self.host_cursor * mon.PARTY_MON_SIZE
                self.party[child_slot] = mon.Mon(
                    bytes(self._host_party[off:off + mon.PARTY_MON_SIZE]))
                self.round += 1
                self.confirmed += 1
                self._req200 = 0
                self._host_party = bytearray(600)
                self._host_party_i = 0
                base = 5 + (self.round - 1) * 6
                for n in range(base, base + 6):
                    self._queue_standby(n)
            elif cmd == trade.BOTH_CANCEL_TRADE:
                self.cancel_seen = True
                self._queue_standby(20)
            return
        if count == trade.COUNT_TRAINER_CARD:
            self._queue_standby(1)
            return
        if count == trade.COUNT_PARTY:
            _, is_lp = linkplayer.parse_block(data)
            if is_lp:
                return
            if self._host_party_i < 3:
                i = self._host_party_i
                self._host_party[i * 200:(i + 1) * 200] = data[:200]
                self._host_party_i += 1

    def _consume_parent_cmd(self, cmd):
        rec = rfu.parse_slot(cmd)
        if rec is None:
            return
        op = rec["op"]
        if op == rfu.SEND_BLOCK_REQ:
            self._on_block_request(rec["reqtype"])
        elif op == rfu.SEND_BLOCK_INIT:
            self.host_rx.on_init(rec["count"], rec.get("owner_raw"))
        elif op == rfu.SEND_BLOCK:
            was_done = self.host_rx.done
            self.host_rx.on_block(rec["index"], rec["frag"])
            if self.host_rx.done and not was_done:
                data, count = self.host_rx.data(), self.host_rx.count
                self.host_rx.consume()
                self._on_host_block(count, data)
        elif op == rfu.SEND_HELD_KEYS:
            key = rec.get("keycode", 0) & 0xFF
            if key == 0x16:
                self.ready_keys_seen += 1
                self._queue_words(rfu.held_keys_words(0x16))
                self._queue_standby(2)
            elif key == 0x17:
                self.exit_keys_seen += 1
                self._queue_words(rfu.held_keys_words(0x17))
        elif op == rfu.READY_EXIT_STANDBY:
            if rec["count"] == 2 and not self._sent_warp3:
                self._sent_warp3 = True
                self._queue_standby(3)
            elif (self.cancel_seen and not self._sent_return_standby
                  and rec["count"] >= 20):
                self._sent_return_standby = True
                self._queue_standby((rec["count"] + 1) & 0xFFFF)
        elif op == rfu.READY_CLOSE_LINK:
            if not self.close_seen:
                self.close_seen = True
                self._queue_words(rfu.close_link_words(rec["count"]))

    def receive(self, wire, now):
        for delivery in self.rel.receive(wire, now):
            rec = gbaframe.parse_in(delivery.payload)
            if rec is None:
                continue
            if rec["type"] == "A":
                assert rec["connect_id"] == self.connect_id
                self.accept_seen = True
                game_data = ni.build_game_data(5, 0x2288, "SWITCH")
                self.ni_send = ni.NISender(game_data)
            elif rec["type"] == "T":
                self.k_seq += 1
                self._queue_reliable_gba(
                    gbaframe.build_k(self.k_seq, 1, rec["ts"]), now)
                if rec.get("ni") is not None:
                    self.ni_frames_in += 1
                    ack = self.ni_recv.on_host_ni(rec["ni"])
                    if ack is not None:
                        self._queue_reliable_gba(gbaframe.wrap_t(ack, self.ts), now)
                        self.ts += 1
                    if self.ni_recv.complete:
                        self.uni_ready = True
                elif rec.get("slots"):
                    self.uni_frames_in += 1
                    rows = dict(rec["slots"])
                    if 0 in rows:
                        self._consume_parent_cmd(rows[0])
            elif rec["type"] == gbaframe.TYPE_D:
                self.disconnect_seen = True

    def _queue_reliable_gba(self, frame, now):
        # Filled by advance(); immediate responses use this small side queue so
        # receive() never reaches into the radio/orchestrator.
        self._gba_pending.append((bytes(frame), now))

    def advance(self, now):
        if self.disconnect_seen:
            pass
        elif self.ni_send is not None and not self.ni_send.done:
            slot = self.ni_send.next_slot()
            self.ni_frames_out += 1
            self._gba_pending.append((gbaframe.wrap_t(slot, self.ts), now))
            self.ts += 1
        elif self.uni_ready:
            if self._awaiting_select and not self._cmd_slots:
                self._post_ribbon_idle += 1
                # A human follower cannot choose until both sides have left BufferTradeParties.
                # Keep the scripted choice beyond the host's bridge quiescence window too.
                if self._post_ribbon_idle >= PARTY_LINK_SETTLE_FRAMES + 5:
                    self._awaiting_select = False
                    if self.confirmed < self.trades:
                        self._queue_linkcmd(
                            trade.READY_TO_TRADE, self.offered[self.round])
                    elif not self.cancel_seen:
                        self._queue_linkcmd(trade.REQUEST_CANCEL)
            cmd = (self._cmd_slots.pop(0) if self._cmd_slots
                   else rfu.idle_slot())
            self._gba_pending.append(
                (gbaframe.wrap_t(rfu.uni_slot(cmd), self.ts), now))
            self.ts += 1
            self.uni_frames_out += 1
        pending, self._gba_pending = self._gba_pending, []
        out = []
        for frame, stamped in pending:
            out.append(self.rel.send(frame, stamped))
        return out + self.rel.poll(now)


class LeaderStack:
    def __init__(self, party):
        self.session = HostSession(
            party, trades=2, offered_slots=[0, 1], anim_delay=1,
            reliable_kwargs={"ack_period_ms": 5, "rto_bootstrap_ms": 20},
            rfu_kwargs={"host_session_id": b"\xb7\xf1"})
        self.rel = self.session.reliable
        self.rfu = self.session.rfu
        self.trade = self.session.trade
        self.events = []

    @property
    def close_frame_queued(self):
        return self.session.close_poll_sent

    @property
    def disconnect_queued(self):
        return self.session.disconnect_sent

    def receive(self, wire, now):
        self.events.extend(self.session.receive_reliable(wire, now))

    def advance(self, now):
        return self.session.tick(now)


def _run_full_stack(max_ms=12000):
    host_original = [_mon(0x11), _mon(0x12)]
    child_original = [_mon(0x21), _mon(0x22)]
    host = LeaderStack(host_original)
    child = ScriptedFireRedChild(child_original)
    radio = ImpairedRadio()

    for emission in child.start(0):
        radio.send("child", emission, 0)

    for now in range(max_ms):
        for packet in radio.deliver(now):
            if packet.direction == "child":
                host.receive(packet.wire, now)
            else:
                child.receive(packet.wire, now)

        for emission in host.advance(now):
            radio.send("host", emission, now)
        for emission in child.advance(now):
            radio.send("child", emission, now)

        if (host.trade.done and child.disconnect_seen
                and host.rel.inflight == child.rel.inflight == 0
                and not radio.pending):
            return host, child, radio, host_original, child_original, now
    raise AssertionError(
        f"full stack timed out: t={max_ms} host={host.trade.state} "
        f"rfu={host.rfu.state} commits={host.trade.commits} "
        f"child_confirmed={child.confirmed} pending={len(radio.pending)} "
        f"inflight={host.rel.inflight}/{child.rel.inflight}")


def test_two_trades_survive_loss_duplicate_reordering_and_close_cleanly():
    host, child, radio, host_original, child_original, elapsed = _run_full_stack()

    assert host.rel.local_opened and host.rel.peer_opened
    assert child.rel.local_opened and child.rel.peer_opened
    assert ("child", 0xFFF0, reliable.METADATA_FRAME) in radio.initialized
    assert any(direction == "host" and seq == 0xFFF0
               and gbaframe.parse_in(payload)["type"] == "A"
               for direction, seq, payload in radio.initialized)
    assert radio.control_frames["host"] > 0
    assert radio.control_frames["child"] > 0
    assert "connect" in host.events and child.accept_seen
    assert host.rfu.child_game_data is not None and child.ni_recv.complete
    assert host.rfu.child_trainer_id == 0x2288
    assert host.rfu.state == DISCONNECTED
    assert host.rfu.uni_in > 0 and host.rfu.uni_out > 0
    assert child.uni_frames_in > 0 and child.uni_frames_out > 0

    assert host.trade.commits == child.confirmed == 2
    assert [m.raw for m in host.trade.received_mons] == [
        child_original[0].raw, child_original[1].raw]
    assert [m.raw for m in host.trade.party] == [
        child_original[0].raw, child_original[1].raw]
    assert [m.raw for m in child.party] == [
        host_original[0].raw, host_original[1].raw]

    assert child.cancel_seen and child.close_seen and child.disconnect_seen
    assert child.ready_keys_seen == 1 and child.exit_keys_seen == 1
    assert host.close_frame_queued and host.disconnect_queued
    assert host.trade.state == H_DONE and host.trade.done
    assert host.rel.inflight == child.rel.inflight == 0

    assert set(radio.dropped) == radio.drop_once
    assert set(radio.duplicated) == radio.duplicate_once
    assert radio.reordered > 0
    assert all(radio.attempts[key] >= 2 for key in radio.drop_once)
    assert elapsed < 12000


def test_leader_cumulatively_acks_connect_before_opening_with_a():
    host = LeaderStack([_mon(0x11), _mon(0x12)])
    child = reliable.HostReliableSession(ack_period_ms=5,
                                         rto_bootstrap_ms=20)
    init = child.open(reliable.METADATA_FRAME, 0)
    connect = child.send(gbaframe.build_connect(b"\x80\x84"), 1)

    # Reproduce 7.2 exactly: the child waits for its INIT ACK before C. An
    # ACK that covers only INIT must not unlock A.
    host.receive(init.serialize(), 0)
    init_outputs = host.advance(6)
    assert len(init_outputs) == 1
    init_ack_id, _ = reliable.parse_bulk_ack(init_outputs[0].payload)
    assert init_ack_id == 0xFFF1
    assert not host.rel.local_opened

    host.receive(connect.serialize(), 7)
    assert host.advance(11) == []
    outputs = host.advance(13)
    assert len(outputs) == 2
    assert outputs[0].flagsA == reliable.FLAGSA_CTRL
    ack_id, _ = reliable.parse_bulk_ack(outputs[0].payload)
    assert ack_id == 0xFFF2
    assert outputs[1].flagsA == reliable.FLAGSA_INIT
    assert gbaframe.parse_in(outputs[1].payload)["type"] == "A"


def main():
    test_leader_cumulatively_acks_connect_before_opening_with_a()
    test_two_trades_survive_loss_duplicate_reordering_and_close_cleanly()
    print("host full-stack end-to-end test: OK")


if __name__ == "__main__":
    main()
