"""Pia MESSAGE tiling + Reliable(10) sub-header (the inverse of the wire parser).

A decrypted+decompressed Pia application blob =
    <message>* <2-byte sender station-id footer> <optional 0xff padding>
Each message has a presence-flag header (fields inherit from the previous message when their
bit is clear) then `size` payload bytes. The trade rides proto=Reliable(10); its 8-byte
sub-header carries the wrap-aware BE seq/window-base and then the emulator frame (flagsA=0x07).
"""

from dataclasses import dataclass, field

PROTO_NAMES = {1: "Net", 3: "RTT", 4: "Sync", 5: "Unreliable",
               9: "Clock", 10: "Reliable", 13: "Session"}
PROTO_RELIABLE = 10

# Station-id footer tokens (BE u16). The reference capture: HOST var=0x7620, JOINER var=0xc493 (were SWAPPED).
# The footer is the RECIPIENT var, so an OUT guest->host blob's footer = STATION_HOST (0x7620).
STATION_HOST = 0x7620
STATION_JOINER = 0xc493

# Reliable sliding-window flags: 1=AppData 2=MsgStart 4=MsgEnd 8=Initialized. A single-fragment app
# message sets Start|End|AppData. Bits 0x10/0x20/0x40 (zlib/Reset/ResetAck) exist in the wider Pia
# protocol but are not used by this title; only these four are honored.
FLAGSA_GBA = 0x07       # AppData|Start|End - a complete single-fragment emulator data frame
FLAGSA_INIT = 0x0f      # FLAGSA_GBA|Initialized - the stream-opening frame; the peer ignores reliable
                        # DATA until it receives one, then seeds its receive base from that frame's seq
FLAGSA_CTRL = 0x00      # no AppData -> the payload is bulk-acknowledgement data

# Reliable RTO / sizing. All times are in MILLISECONDS - the protocol computes its retransmit timeout
# and its delayed-ack interval in ms, so the link is driven with a millisecond clock.
RTO_BASE_MS = 33        # RTO base; also the delayed-ack interval (a standalone ack is owed this often)
RTO_RTT_FACTOR = 1.4    # RTT term in the RTO: RTO = RTO_BASE_MS + RTO_RTT_FACTOR * median(RTT). No
                        # exponential backoff and no clamp - every (re)send re-arms the same deadline.
RTT_WINDOW = 7          # the RTO uses the MEDIAN of the most recent <=7 round-trip samples, so a single
                        # jittered/bufferbloated spike cannot inflate it the way a running average would.
MAX_INFLIGHT = 128      # the selective-ack mask spans 128 sequence ids, so at most 128 frames can be
                        # outstanding past the cumulative ack point.

# The emulator's FIRST Reliable payload is a title/version metadata frame, carried on the stream-opening
# (INIT) frame (LeafGreen, English - a FireRed host accepts it).
METADATA_FRAME = bytes.fromhex("4a002a005801004c656166477265656e5f65" + "00" * 28)


def build_bulk_ack(next_expected, mask=b"\x00" * 16, stream_id=0):
    """Bulk-acknowledgement payload for a FLAGSA_CTRL frame: stream id, entry count, then per entry an
    ack id (every seq below it is acked) + a 128-bit selective mask. Unicast carries a single entry:
    `<stream_id> 01 <next_expected:2 BE> <16-byte mask>` (e.g. acking up through fff0 -> 0001fff1)."""
    return bytes([stream_id & 0xFF, 1]) + (next_expected & 0xFFFF).to_bytes(2, "big") + mask


def parse_bulk_ack(payload):
    """-> (ack_id, mask) from a FLAGSA_CTRL payload. ack_id = next-expected seq (every seq below it
    is acked); mask = 128-bit gap bitmap (`ack_id + index` is acked when bit `index` is set;
    bit zero is normally clear because ack_id itself is the cumulative hole).
    Returns (None, b'') if too short."""
    if len(payload) < 4:
        return None, b""
    return int.from_bytes(payload[2:4], "big"), payload[4:20].ljust(16, b"\x00")


def _seq_lt(a, b):
    """a < b in 16-bit wrap-around sequence space (RFC1982-style)."""
    d = (b - a) & 0xFFFF
    return d != 0 and d < 0x8000


# A buffered send entry is [flagsA, inner, last_tx_ms, resends, acked].
_E_FLAGS, _E_INNER, _E_LASTTX, _E_RESENDS, _E_ACKED = range(5)


class ReliableLink:
    """A Pia reliable sliding window (one per peer), selective-repeat in both directions. Frames drop on
    this radio and an un-retransmitted reliable stream deadlocks the instant one does (the peer stalls on
    the gap), so it does the full job:

      * SEND: hands out sequence ids, BUFFERS every unacked data frame, and re-offers any frame whose RTO
        has elapsed (or that the peer selective-NACKs) until the peer's bulk-ack frees it.
      * RECV: delivers data frames to the app IN ORDER, BUFFERS out-of-order frames across a gap, and
        DEDUPES retransmits, so a dropped/duplicated frame never corrupts the emulator stream.

    All times are in MILLISECONDS. Control/ack frames are not tracked here (they carry no sequence id);
    the sim sends them at the window base. `window_lo` is the header's "lowest pending ack" field, i.e.
    the send-window base."""

    def __init__(self, start=0xFFF0, max_inflight=MAX_INFLIGHT, rtt_jitter_k=0.0,
                 dup_nack_threshold=1, rto_ceil_ms=None, rto_backoff=1.0, rto_bootstrap_ms=None):
        """The keyword knobs default to the CONSOLE-FAITHFUL behavior; a link whose peer doesn't behave
        like the console (a userspace Wi-Fi bridge to a host that pauses for save-writes and consumes the
        reliable stream slowly) sets them to compensate. Each divergence and its reason is documented at
        rto() / due_retransmits, and in the driver that supplies the values.
          rtt_jitter_k        0    -> RTO = base + 1.4*median only (console). >0 adds a variance margin.
          dup_nack_threshold  1    -> fast-retransmit on the FIRST NACK (console). >1 requires that many.
          rto_ceil_ms         None -> no RTO clamp (console). A value clamps the RTO from ABOVE.
          rto_backoff         1.0  -> no backoff: every resend re-arms the SAME RTO (console). >1 multiplies
                                      the RTO per resend, so a peer that has gone quiet (mid save-write) is
                                      not machine-gunned with retransmits it cannot answer yet.
          rto_bootstrap_ms    None -> no timer until the first RTT sample (console). A value is the RTO used
                                      ONLY while we have NO RTT samples yet (the connect phase) - so reliable
                                      frames sent before any round-trip (the J/C connect handshake) still
                                      RETRANSMIT until the peer's reliable side comes up, instead of being
                                      sent once and lost. It is NOT a floor: once RTT samples exist the pure
                                      RTT formula is used (no min), keeping the trade phase fast (see rto())."""
        self.out_seq = start              # next send sequence id to hand out
        self.window_lo = start            # send-window base = lowest seq still awaiting ack (header field)
        self.unacked = {}                 # seq -> entry (see _E_* layout above)
        self.recv_next = start            # next in-order seq we expect from the peer (contiguous high-water)
        self.recv_buf = {}                # seq -> payload buffered across a gap (offline on_data path)
        self.recv_ooo = set()             # out-of-order received seqs > recv_next (live path); drives the
                                          # selective ack mask. Populated by note_received(); empty on on_data.
        self.max_inflight = max_inflight
        self._rtt = []                    # most recent <=RTT_WINDOW round-trip samples (ms); RTO uses the median
        self._rtt_jitter_k = rtt_jitter_k
        self._dup_nack_threshold = max(1, dup_nack_threshold)
        self._rto_ceil_ms = rto_ceil_ms
        self._rto_backoff = rto_backoff
        self._rto_bootstrap_ms = rto_bootstrap_ms
        self._peer_gap = None             # the seq the peer is currently selective-NACKing (the hole)
        self._gap_nacks = 0               # consecutive acks that NACKed _peer_gap (the dup-NACK count)

    # -- send side --------------------------------------------------------
    def inflight(self):
        return len(self.unacked)

    def send_low(self):
        """The header 'lowest sequence id pending ack' field = the send-window base: our oldest seq still
        awaiting ack, or out_seq when nothing is outstanding."""
        return self.window_lo if self.unacked else self.out_seq

    def queue(self, inner, flagsA, now_ms):
        """Assign a sequence id to a new DATA frame and buffer it for retransmission. now_ms stamps its
        send time for the RTO timer."""
        seq = self.out_seq
        self.out_seq = (self.out_seq + 1) & 0xFFFF
        self.unacked[seq] = [flagsA, inner, now_ms, 0, False]
        return seq

    def add_rtt_sample(self, rtt_ms):
        """Record a peer round-trip-time sample (ms). The RTO uses the MEDIAN of the most recent
        RTT_WINDOW samples, so a single jittered/bufferbloated spike cannot inflate it. The samples are
        the round-trip of un-retransmitted reliable frames, measured in on_ack (a frame acked without
        ever being resent gives an unambiguous round-trip); an external RTT probe may add more here."""
        if rtt_ms is None or rtt_ms < 0:
            return
        self._rtt.append(float(rtt_ms))
        if len(self._rtt) > RTT_WINDOW:
            self._rtt = self._rtt[-RTT_WINDOW:]

    def rto(self):
        """Retransmit timeout in MILLISECONDS. CONSOLE-FAITHFUL core: RTO_BASE_MS + RTO_RTT_FACTOR *
        median(last <=RTT_WINDOW samples) - no backoff, no floor - which, with the default knobs
        (rtt_jitter_k=0, rto_ceil_ms=None, rto_bootstrap_ms=None), is exactly the console's algorithm. With
        RTT samples present it is ALWAYS the pure formula (no minimum), so the trade phase stays fast.

        DIVERGENCE for high-jitter links (rtt_jitter_k>0): the median tracks the TYPICAL RTT, but on a link
        whose RTT ranges from ~50ms to ~1s a median-only RTO retransmits every slow-but-not-lost frame
        prematurely. So we add rtt_jitter_k * MAD (mean absolute deviation of the RTT window) to cover the
        spread, optionally clamped by rto_ceil_ms to keep recovery under the peer's link timeout. On a
        low-jitter console link MAD~=0, so this term vanishes and the formula is identical to the binary.

        BOOTSTRAP (rto_bootstrap_ms set): until the FIRST RTT sample arrives there is nothing to time from,
        so the console returns None (no timer-driven retransmit). On the bridge that loses the connect-phase
        reliable frames: the J/C handshake is sent BEFORE any round-trip, the host's reliable side isn't up
        yet (it engages ~2s in, in RESPONSE to our J/C), and a one-shot J/C is simply lost -> the host never
        sees our connect -> deadlock. So rto_bootstrap_ms arms a constant RTO while sampleless, making those
        frames retransmit until the host engages. It is a BOOTSTRAP, NOT a floor: the instant we have samples
        the pure formula takes over with no minimum (an earlier floor was measured to SLOW the trade ~2x)."""
        if self._rtt:
            s = sorted(self._rtt)
            median = s[len(s) // 2]
            rto = RTO_BASE_MS + RTO_RTT_FACTOR * median
            if self._rtt_jitter_k:
                mad = sum(abs(x - median) for x in self._rtt) / len(self._rtt)
                rto += self._rtt_jitter_k * mad
        elif self._rto_bootstrap_ms is not None:
            rto = self._rto_bootstrap_ms      # no samples yet -> arm a constant RTO so connect frames retransmit
        else:
            return None                       # console: no timer until the first RTT sample
        if self._rto_ceil_ms is not None:
            rto = min(rto, self._rto_ceil_ms)
        return rto

    def on_ack(self, ack_id, mask=None, now_ms=None):
        """Process the peer's bulk-ack. A frame is acknowledged when it is in the cumulative run below
        ack_id, OR when the selective mask marks it received (bit i set => ack_id+i received, LSB-first
        within each byte). Acknowledged frames stop being retransmitted immediately, but the window base
        only advances over the CONTIGUOUS acknowledged run from the base - a mask-acked frame above a gap
        keeps its slot until the gap fills. This is the selective-repeat sender: holes are retransmitted,
        frames the peer already has are not, and the window does not over-advance past an unfilled gap.

        RTT: if now_ms is given, the FIRST acknowledgment of an un-retransmitted frame - by cumulative ack
        OR selective mask - yields its round-trip sample. Sampling on the mask (not only the cumulative
        ack) is deliberate: a frame that arrived out of order is acked by the mask immediately, whereas the
        cumulative ack only passes it once the earlier gap fills, which would over-measure the RTT by the
        head-of-line delay. (The console reads RTT from the separate RTT protocol and sidesteps this; over
        the bridge that protocol returns no samples, so we self-measure here and must avoid the HOL bias.)"""
        if ack_id is None:
            return
        maskint = int.from_bytes(mask, "little") if mask else 0
        for seq, entry in self.unacked.items():
            arrived = _seq_lt(seq, ack_id)                 # cumulative run below ack_id
            if not arrived and maskint:                    # selective mask: bit i => ack_id+i received
                # Bit zero corresponds to ack_id itself.  Since ack_id is the
                # cumulative hole that bit is normally clear; the first
                # out-of-order sequence (ack_id + 1) is bit one.  Native
                # capture example: ack_id=fff7, mask=06 marks fff8+fff9.
                i = (seq - ack_id) & 0xFFFF
                arrived = i < 128 and bool((maskint >> i) & 1)
            if arrived and not entry[_E_ACKED]:
                if now_ms is not None and entry[_E_RESENDS] == 0:
                    self.add_rtt_sample(now_ms - entry[_E_LASTTX])   # true-arrival (Karn-clean) RTT sample
                entry[_E_ACKED] = True
        # advance the window base over the contiguous acknowledged run only (freeing those slots); stop at
        # the first hole, so a mask-acked frame above the hole stays buffered (occupying a slot) until the
        # hole fills.
        while self.window_lo in self.unacked and self.unacked[self.window_lo][_E_ACKED]:
            del self.unacked[self.window_lo]
            self.window_lo = (self.window_lo + 1) & 0xFFFF
        # track the peer's current hole and how many acks have NACKed it (the dup-NACK count) - due_retransmits
        # fast-retransmits it once dup_nack_threshold acks agree it is missing.
        if maskint and ack_id in self.unacked and not self.unacked[ack_id][_E_ACKED]:
            if ack_id == self._peer_gap:
                self._gap_nacks += 1
            else:
                self._peer_gap = ack_id
                self._gap_nacks = 1
        else:
            self._peer_gap = None
            self._gap_nacks = 0

    def due_retransmits(self, now_ms, limit=None):
        """[(seq, flagsA, inner)] for unacked frames due to resend (oldest first); stamps them re-sent.
        Two triggers, NO exponential backoff:
          - FAST-RETRANSMIT: the peer's current hole (_peer_gap) is resent ONCE, but only after
            dup_nack_threshold acks have agreed it is missing. On the console that threshold is 1 (a single
            NACK => loss). DIVERGENCE for high-jitter links: there a single NACK does NOT imply loss - a
            slow frame is often still in flight when the peer NACKs it - so the driver raises the threshold
            (several agreeing NACKs = really gone, not just reordered) to stop resending in-flight frames.
            After the one fast-retransmit the frame is governed by the timer.
          - TIMEOUT: a frame is resent when now_ms - last_tx >= its RTO. With the console default
            (rto_backoff=1.0) the RTO is rto() re-armed to the same value on every resend; with backoff>1
            it grows as rto() * backoff**resends (clamped by rto_ceil_ms), so a peer that has gone quiet
            isn't re-sent the same frame every rto().
        Acknowledged-but-not-yet-freed frames are never retransmitted. Until the first RTT sample arrives
        rto() is None, so only the (one-shot) fast-retransmit trigger fires.
        limit=None returns ALL due frames (gap order); limit=N is gap-targeted (the oldest <=N, stopping at
        the first not-yet-due frame) so the in-flight count stays bounded."""
        base_rto = self.rto()
        out = []
        for seq in sorted(self.unacked, key=lambda s: (s - self.window_lo) & 0xFFFF):
            entry = self.unacked[seq]
            if entry[_E_ACKED]:
                continue                                   # peer already has it -> never retransmit
            if (seq == self._peer_gap and entry[_E_RESENDS] == 0
                    and self._gap_nacks >= self._dup_nack_threshold):
                due = True                                 # confirmed hole, not yet resent -> fast-retransmit ONCE
            elif base_rto is None:                         # no RTT sample yet -> no timer retransmit
                due = False
            else:
                eff_rto = base_rto * (self._rto_backoff ** entry[_E_RESENDS])
                if self._rto_ceil_ms is not None:
                    eff_rto = min(eff_rto, self._rto_ceil_ms)
                due = (now_ms - entry[_E_LASTTX]) >= eff_rto
            if due:
                entry[_E_LASTTX] = now_ms
                entry[_E_RESENDS] += 1
                out.append((seq, entry[_E_FLAGS], entry[_E_INNER]))
                if limit is not None and len(out) >= limit:
                    break
            elif limit is not None:
                break          # gap-targeted: don't skip past a not-yet-due frame to re-send buffered ones
        return out

    # -- receive side -----------------------------------------------------
    def on_data(self, seq, payload):
        """Accept a received DATA frame; return the list of payloads now deliverable IN ORDER (empty for a
        future/duplicate frame). The offline path: buffers across a gap and delivers cumulatively (its ack
        therefore carries a zero selective mask)."""
        if seq == self.recv_next:
            out = [payload]
            self.recv_next = (self.recv_next + 1) & 0xFFFF
            while self.recv_next in self.recv_buf:
                out.append(self.recv_buf.pop(self.recv_next))
                self.recv_next = (self.recv_next + 1) & 0xFFFF
            return out
        if _seq_lt(self.recv_next, seq):              # ahead of the gap -> buffer it
            self.recv_buf[seq] = payload
        return []                                     # duplicate/old, or buffered

    def note_received(self, seq):
        """Selective-repeat receiver accounting for the live path: record a received DATA seq without
        in-order delivery (the emulator processes frames as they arrive, order-tolerant). Advances
        recv_next over the contiguous run and keeps out-of-order seqs in recv_ooo for the selective ack
        mask, so the peer fast-retransmits exactly its dropped frames. Idempotent."""
        if seq == self.recv_next:
            self.recv_next = (self.recv_next + 1) & 0xFFFF
            while self.recv_next in self.recv_ooo:
                self.recv_ooo.discard(self.recv_next)
                self.recv_next = (self.recv_next + 1) & 0xFFFF
        elif _seq_lt(self.recv_next, seq):
            self.recv_ooo.add(seq)
        # else: seq < recv_next (already counted) or duplicate -> ignore

    def ack_payload(self):
        """Bulk-ack: CUMULATIVE next-expected (recv_next) + a SELECTIVE MASK of the out-of-order frames we
        hold (recv_ooo), so the peer fast-retransmits exactly its dropped frames (mask bit i set =>
        recv_next+i received, LSB-first within each byte; bit zero is the cumulative hole and is clear).
        recv_ooo is populated by note_received (live
        path); on the offline on_data path it stays empty -> zero mask (cumulative-only)."""
        mask = bytearray(16)
        for s in self.recv_ooo:
            i = (s - self.recv_next) & 0xFFFF
            if i < 128:
                mask[i >> 3] |= (1 << (i & 7))
        return build_bulk_ack(self.recv_next, bytes(mask))


@dataclass(frozen=True)
class ReliableEmission:
    """One Reliable message ready for the Pia framing layer.

    The host driver deliberately owns Pia addressing, packet ids, encryption,
    batching and transmission.  Keeping those concerns out of the Reliable
    state machine makes loss/reordering tests deterministic and lets both host
    and client transports reuse the same wire codec.
    """

    seq: int
    flagsA: int
    ack: int
    payload: bytes
    retransmitted: bool = False

    @property
    def message_flags(self):
        # Both native peers put Pia MESSAGE flag 0x40 on pure bulk ACKs and
        # 0x20 on retransmitted DATA.  These are mutually exclusive here:
        # control ACKs are never tracked/retransmitted by ReliableLink.
        if self.flagsA == FLAGSA_CTRL:
            return 0x40
        return 0x20 if self.retransmitted else None

    def serialize(self):
        return build_reliable(self.seq, self.ack, self.payload, self.flagsA)


@dataclass(frozen=True)
class ReliableDelivery:
    """An in-order, de-duplicated DATA frame delivered by HostReliableSession."""

    seq: int
    flagsA: int
    payload: bytes


class HostReliableSession:
    """Transport-independent Pia Reliable leader state machine.

    ``open`` opens the local stream with the caller's first RFU frame.
    ``receive`` consumes a peer Reliable sub-frame and returns newly available
    DATA in sequence order.  ``poll`` emits timer/fast retransmissions and the
    native 0x40 bulk ACK.  New RFU frames are added with ``send``.  Every
    returned :class:`ReliableEmission` is wrapped as a proto-10 Pia message by
    the caller; the class never touches sockets, crypto, or packet-id counters.

    The leader and joiner use independent 16-bit streams, both starting at
    FFF0 in FireRed/LeafGreen.  The roles use different opening payloads: the
    joiner sends the title metadata, while the native leader first sends its
    RFU ``A`` accept as an Initialized DATA frame.  Requiring that payload in
    ``open`` prevents the leader from accidentally copying the joiner flow.
    A small bootstrap RTO keeps the opening frame alive before RTT samples have
    reached the Reliable layer.  Once
    ``note_rtt`` is called, ReliableLink's native median-driven RTO takes over.
    """

    def __init__(self, start=0xFFF0, *, ack_period_ms=RTO_BASE_MS,
                 max_inflight=MAX_INFLIGHT, rto_bootstrap_ms=200,
                 dup_nack_threshold=1, retransmit_limit=None):
        self.start_seq = start & 0xFFFF
        self.link = ReliableLink(
            start=self.start_seq,
            max_inflight=max_inflight,
            rto_bootstrap_ms=rto_bootstrap_ms,
            dup_nack_threshold=dup_nack_threshold,
        )
        self.ack_period_ms = float(ack_period_ms)
        self.retransmit_limit = retransmit_limit
        self.local_opened = False
        self.peer_opened = False
        self._ack_owed = False
        self._next_ack_ms = None

        # Delivery ordering is intentionally separate from ReliableLink's
        # receive ACK accounting.  The latter advances immediately and keeps a
        # selective mask; this buffer holds application data across a gap so
        # RFU never observes reordering or duplicate retransmits.
        self._deliver_next = self.start_seq
        self._deliver_buf = {}

    @property
    def inflight(self):
        return self.link.inflight()

    @property
    def recv_next(self):
        return self.link.recv_next

    def _emission(self, seq, flagsA, payload, *, retransmitted=False):
        # ACK/window-base is sampled at actual emission time, including a
        # retransmission, rather than frozen when the DATA was first queued.
        return ReliableEmission(seq & 0xFFFF, flagsA, self.link.send_low(), bytes(payload),
                                retransmitted=retransmitted)

    def open(self, payload, now_ms, flagsA=FLAGSA_GBA):
        """Open the leader stream with its first RFU payload.

        Native FRLG uses ``A`` (connect accept) here, with Initialized added to
        the ordinary AppData|Start|End flags.  The method is idempotent so a
        duplicate child ``C`` cannot allocate a second opening sequence id.
        """
        if self.local_opened:
            return None
        flagsA = (int(flagsA) | FLAGSA_INIT) & 0xFF
        payload = bytes(payload)
        seq = self.link.queue(payload, flagsA, now_ms)
        self.local_opened = True
        return self._emission(seq, flagsA, payload)

    def send(self, payload, now_ms, flagsA=FLAGSA_GBA):
        """Queue one DATA/RFU frame and return the first transmission.

        Callers must respect the peer-facing send window.  Raising instead of
        silently dropping a frame makes backpressure explicit at integration
        boundaries.
        """
        if not self.local_opened:
            raise RuntimeError("Reliable stream has not been opened")
        if self.link.inflight() >= self.link.max_inflight:
            raise BufferError("Reliable send window is full")
        flagsA = int(flagsA) & 0xFF
        if not (flagsA & 0x01):
            raise ValueError("send() is for Reliable DATA frames, not control ACKs")
        seq = self.link.queue(bytes(payload), flagsA, now_ms)
        return self._emission(seq, flagsA, payload)

    def note_rtt(self, rtt_ms):
        """Feed a completed Pia RTT probe into retransmission timing."""
        self.link.add_rtt_sample(rtt_ms)

    def _deliver(self, frame):
        seq = frame.seq
        if seq == self._deliver_next:
            ready = [ReliableDelivery(seq, frame.flagsA, bytes(frame.payload))]
            self._deliver_next = (self._deliver_next + 1) & 0xFFFF
            while self._deliver_next in self._deliver_buf:
                buffered = self._deliver_buf.pop(self._deliver_next)
                ready.append(ReliableDelivery(
                    buffered.seq, buffered.flagsA, bytes(buffered.payload)))
                self._deliver_next = (self._deliver_next + 1) & 0xFFFF
            return ready
        if _seq_lt(self._deliver_next, seq):
            self._deliver_buf.setdefault(seq, frame)
        return []

    def receive(self, wire, now_ms):
        """Consume one serialized Reliable sub-frame.

        Returns only newly in-order DATA deliveries.  Control frames update the
        send window and RTT estimator but are never acknowledged themselves.
        Malformed/truncated frames are ignored.
        """
        frame = parse_reliable(bytes(wire))
        if frame is None or frame.raw_len > len(wire) - 8:
            return []
        if not (frame.flagsA & 0x01):
            ack_id, mask = parse_bulk_ack(frame.payload)
            self.link.on_ack(ack_id, mask, now_ms=now_ms)
            return []

        # The peer's fff0 stream-opening DATA must carry Initialized.  Do not
        # let a malformed/plain frame consume that sequence slot: otherwise a
        # later valid INIT would look like a duplicate and the stream could
        # never open.  Future frames may arrive first and are safely SACKed /
        # buffered across the fff0 gap.
        if (not self.peer_opened and frame.seq == self.start_seq
                and not (frame.flagsA & 0x08)):
            return []
        if frame.flagsA & 0x08:
            self.peer_opened = True
        self.link.note_received(frame.seq)
        self._ack_owed = True
        if self._next_ack_ms is None:
            self._next_ack_ms = float(now_ms) + self.ack_period_ms
        return self._deliver(frame)

    def poll(self, now_ms):
        """Return due retransmissions followed by at most one bulk ACK."""
        emissions = [
            self._emission(seq, flagsA, payload, retransmitted=True)
            for seq, flagsA, payload in self.link.due_retransmits(
                now_ms, limit=self.retransmit_limit)
        ]
        ack_due = (self._next_ack_ms is not None
                   and float(now_ms) >= self._next_ack_ms)
        if ack_due and (self._ack_owed or self.link.recv_ooo):
            emissions.append(ReliableEmission(
                self.start_seq, FLAGSA_CTRL, self.link.send_low(),
                self.link.ack_payload()))
            self._ack_owed = False
            # Keep selectively NACKing a persistent gap at the delayed-ACK
            # cadence; otherwise no more ACK is scheduled until new DATA.
            self._next_ack_ms = (float(now_ms) + self.ack_period_ms
                                 if self.link.recv_ooo else None)
        return emissions


@dataclass
class Message:
    flags: int
    proto: int
    size: int
    payload: bytes
    msgflags: int = 0
    hdr_bytes: bytes = b""          # exact header slice (for byte-identical reserialization)

    def serialize(self):
        return self.hdr_bytes + self.payload


def parse_messages(data):
    """Tile a Pia application blob into messages. Returns (list[Message], consumed)."""
    msgs = []
    i, n = 0, len(data)
    mf, size, proto = 0, None, None
    while i < n:
        fl = data[i]
        if fl == 0xff or (fl & 0xF0):
            break
        if fl == 0 and size is None:
            break
        hdr_start = i
        j = i + 1
        if fl & 1:
            if j >= n:
                break
            mf = data[j]
            j += 1
        if fl & 2:
            if j + 2 > n:
                break
            size = int.from_bytes(data[j:j + 2], "big")
            j += 2
        if fl & 4:
            if j >= n:
                break
            proto = data[j]
            j += 1
        if fl & 8:
            # 6.32-6.40 format: bit 0x8 = a 1-byte PORT (the 5.27-6.30 format had an 8-byte u64 dest
            # here, which mis-tiled the stream the moment a host set this bit). (Bit 0x10 is
            # rejected by the high-nibble guard above and never appears on this title, so it is not
            # tiled here - relaxing that guard would risk mis-parsing padding for no live benefit.)
            if j + 1 > n:
                break
            j += 1                      # destination port (1 byte)
        if size is None or j + size > n:
            break
        msgs.append(Message(flags=fl, msgflags=mf, proto=proto, size=size,
                            payload=data[j:j + size], hdr_bytes=data[hdr_start:j]))
        i = j + size
    return msgs, i


def build_message(proto, payload, msgflags=None):
    """Build a self-contained message header (all fields present, no inheritance) + payload.
    flags bit0=msgflags bit1=size bit2=proto. We always set size+proto so the message parses
    standalone; msgflags is included only when given."""
    flags = 0x02 | 0x04
    hdr = bytearray()
    if msgflags is not None:
        flags |= 0x01
    hdr.append(flags)
    if msgflags is not None:
        hdr.append(msgflags & 0xFF)
    hdr += len(payload).to_bytes(2, "big")
    hdr.append(proto & 0xFF)
    return bytes(hdr) + payload


@dataclass
class Reliable:
    """Reliable(10) sub-header (big-endian) + inner payload:
        flags(1) size(2) seq(2) window_base(2) N(1) [payload]
    `window_base` is the sender's own lowest-pending-ack (carried in the `ack` field for back-compat).
    N is the multicast recipient count, 0 for unicast (no recipient bitmap follows)."""
    flagsA: int
    seq: int
    ack: int            # the sender's window base (lowest pending ack)
    payload: bytes
    raw_len: int = 0

    def serialize(self):
        return (bytes([self.flagsA]) + len(self.payload).to_bytes(2, "big")
                + self.seq.to_bytes(2, "big") + self.ack.to_bytes(2, "big")
                + bytes([0x00]) + self.payload)


def parse_reliable(payload):
    """Reliable(10) 8-byte sub-header then inner payload[size]. size is a 2-byte big-endian field at
    [1:3]; byte 7 is the multicast count (0 for unicast)."""
    if len(payload) < 8:
        return None
    ln = int.from_bytes(payload[1:3], "big")
    return Reliable(flagsA=payload[0],
                    seq=int.from_bytes(payload[3:5], "big"),
                    ack=int.from_bytes(payload[5:7], "big"),
                    payload=payload[8:8 + ln], raw_len=ln)


def build_reliable(seq, ack, inner, flagsA=FLAGSA_GBA):
    return Reliable(flagsA=flagsA, seq=seq, ack=ack, payload=inner).serialize()


def parse_app(data):
    """Full application blob -> (messages, station_id_or_None, tail_len). The trailing region
    after the last message is a 2-byte station-id footer then 0xff padding."""
    msgs, consumed = parse_messages(data)
    tail = data[consumed:]
    stripped = tail.rstrip(b"\xff")
    station = int.from_bytes(stripped, "big") if len(stripped) == 2 else None
    return msgs, station, len(tail)


def build_app(messages, station_id=STATION_HOST, pad=0):
    """Concatenate built message bytes + the 2-byte station-id footer (+ optional 0xff pad). Default
    footer = STATION_HOST (the recipient of a guest->host blob)."""
    blob = b"".join(messages) + station_id.to_bytes(2, "big")
    return blob + b"\xff" * pad
