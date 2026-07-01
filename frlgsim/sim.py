"""The per-VBlank orchestrator - wires transport <-> crypto <-> Pia <-> FSM.

Two phases:
  S0 (connection): the ConnectionManager completes Net + Session(new) + RTT so the host
     registers us as a peer (this is what makes the "OK" prompt appear). Until then NO trade
     traffic is emitted.
  S1+ (trade): once connected, the TradeEngine's per-VBlank RFU slots ride Reliable(10).

Station VAR IDs are LEARNED from the wire (Pia header = [dst_var][src_var]; footer = dest var):
on each IN packet we record our id (= header dst) and the host's (= header src) and use them in
every OUT header/footer. Addressing: RTT -> broadcast, Net/Session/Reliable -> unicast to host.
A capture path mirrors every datagram to a .jsonl so it can be decrypted/analysed offline.
"""

import json
import os
import time

from . import crypto as cryptomod, reliable, gbaframe, rfu, pia_connect, ni, linkplayer

RELIABLE_SEQ_START = 0xFFF0

# The reliable layer runs on a millisecond clock; the sim ticks once per VBlank, so convert the VBlank
# counter to ms at the link boundary (timestamps for the RTO timer + RTT samples). 59.727 Hz VBlank.
MS_PER_VBLANK = 1000.0 / 59.727

# Max Reliable messages packed into ONE Pia datagram (observed: the reference capture batches up to 9/datagram). We
# coalesce a VBlank's retransmits + K acks + the T slot + the ctrl-ack into one datagram (chunked at
# this size) instead of one datagram per frame - the prime BufferIsFull lever.
RELIABLE_BATCH_MAX = 9

# LIVE-only cap on NEW standby (0x6600/0x5F00) frames emitted per count (live fix: standby flood
# deadlock). The reference capture sends each standby ~3-4x then stops; emitting every VBlank keeps the host
# in the same round forever (it sees continuous count=N) -> mutual deadlock + buffer flood. Bounding +
# reliable retransmit (live) matches the reference capture. Offline keeps the unbounded cadence its MockHost depends on.
BARRIER_EMITS = 6

# Pia reliable retransmit. The RTO lives entirely in ReliableLink: RTO = 33ms + 1.4*median(RTT), no clamp
# and no exponential backoff, driven by RTT samples taken from the RTT protocol (see _drive_reliable /
# the RTT feed in process_datagram). The retransmit is GAP-TARGETED (RTX_GAP_LIMIT) in the high-volume
# block/trade phase and whole-window for the tiny NI/seat phase (so the few critical NI frames get through).
RTX_GAP_LIMIT = 1          # block/trade phase: re-send only the gap (the peer buffers out-of-order)
RTX_GAP_LIMIT_NI = 2       # NI/seat phase: a slightly longer tail (a few critical frames), still bounded
# Pia reliable congestion control. The reliable layer (frlgsim/reliable.py) defaults to the console's
# settings: a large window, RTO = 33ms + 1.4*median(RTT), and fast-retransmit on a single NACK. The console
# earns those on a near-constant-latency local radio (median RTT ~= max RTT, and a NACK genuinely means
# loss). This LINK is different - userspace Wi-Fi with a ~50ms MEDIAN RTT but a ~1s TAIL (~20x jitter) and
# almost no real loss - so the console settings would collapse into a self-sustaining retransmit storm (a
# NACK fires for a frame merely in flight; the resend adds air contention; contention raises the jitter;
# the jitter creates more apparent gaps). So the driver overrides a few knobs, each a DOCUMENTED DIVERGENCE
# that defaults to the console behavior in reliable.py and only matters because this link breaks the
# console's assumptions:
#
#   MAX_INFLIGHT - the shared reliable send window. It must stay SMALL on this link: a larger window puts
#     more frames in flight than the host's receive side tolerates, and it faults with an in-game
#     Communication error (measured: both 18 and 128 fault shortly before the save; 6 is the ceiling and
#     completes the trade). Emission is FREE-RUN (one datagram per VBlank, below) rather than paced to the
#     host's poll arrivals, so in steady state in-flight self-limits well under the window - the window is
#     the safety cap, not the pacer. (K_INFLIGHT_MAX reserves part of it for the critical 'T' so a K-ack
#     burst can never starve it.)
#   RTT_JITTER_K - the RTO must cover the JITTER, not just the median, or every slow-but-not-lost frame in
#     the 1s tail is retransmitted prematurely. rto() adds K * MAD(RTT) when this is > 0 (0 = console).
#   DUP_NACK_THRESHOLD - require this many agreeing NACKs before fast-retransmitting a hole. One NACK means
#     loss on the console; here it usually means the frame is still in flight (it lands ~50ms-1s later), so
#     resending on a single NACK resends in-flight frames. (The console's dup-NACK field is off / 1; we
#     turn it on for the bridge.)
#   RTO_CEIL_MS - clamp the RTO so a hole recovers in bounded time. The link is fast (~18ms round-trip),
#     so the RTO normally sits ~100ms; the clamp just bounds the worst case.
#   RTO_BACKOFF - DISABLED (1.0 = console). Backoff was tried (the theory being that retransmits were
#     futile resends of frames a slow host already had); it caused a MASSIVE regression - recovery latency
#     blew up to multiple seconds and the post-party-block transfer crawled/deadlocked. So the retransmits
#     are NEEDED, not futile: a stuck frame genuinely takes many sends to get through, and with a lean
#     window one stuck hole blocks the whole window - which means recovery must be FAST, never slowed. Keep
#     backoff off here.
#   RTO_BOOTSTRAP_MS - the RTO used ONLY while we have NO RTT samples yet (the connect phase); NOT a floor.
#     With no samples the console returns no RTO (no timer-driven retransmit) - fine on a clean radio, but on
#     the bridge it LOSES the connect-phase reliable frames: our 'J' (metadata/Initialized) + 'C' (RFU connect)
#     are sent the instant we go CONNECTED (~0.2s), BEFORE any round-trip, but the host's reliable side does
#     not come up until ~2s in (it engages in RESPONSE to our J/C, observed in frlg2/frlg3). A one-shot J/C is
#     simply lost -> the host never registers our connect -> 0 host proto-10 -> the pre-OK deadlock. A bootstrap
#     RTO (~200ms) makes J/C RETRANSMIT until the host engages. It is NOT a floor (the floor was measured to
#     ~2x the trade latency, p50 104->228ms): the instant the FIRST RTT sample arrives the pure formula
#     (33 + 1.4*median + jitter, capped by RTO_CEIL_MS) takes over with no minimum -> trade stays fast
#     (win2-slow-entry: p50 104ms / 5% NACK). So bootstrap fixes connect WITHOUT slowing the trade.
MAX_INFLIGHT = 6          # shared reliable window. Must stay SMALL on this bridge: a larger window lets us
                          # put more frames in flight than the host's receive side tolerates, and it faults
                          # with an in-game Communication error. Re-confirmed on the clean free-run base: 18
                          # comms-errored shortly before the save, exactly like the earlier 128 - so 6 is the
                          # ceiling. (The ~2x retransmit seen at 6 is therefore NOT a window problem; it is the
                          # RTO firing before the host's ack returns - a separate, RTO-side lever.)
RTT_JITTER_K = 4.0
DUP_NACK_THRESHOLD = 3
RTO_CEIL_MS = 670
RTO_BACKOFF = 1.0
RTO_BOOTSTRAP_MS = 200    # RTO while sampleless so the connect J/C retransmit until the host engages (NOT a floor)
# K-ack pacing: the K-ack is the emulator's ack of a received host poll. _drive_reliable emits up to
# K_PER_VBLANK new K-acks per VBlank (the free-run cadence), leaving window room for the 'T'. K_BACKLOG_MAX
# bounds the pending-K list as a memory safety net (K is a monotonic ts ack; the host re-sends un-acked T,
# so dropping the oldest deferred K is safe).
K_BACKLOG_MAX = 32         # pending-K list cap (memory safety net)
# K in-flight cap: at most this many of OUR K-acks unacked at once. K is droppable (monotonic ts ack; the
# host re-sends un-acked T), so capping it RESERVES room in the small window for the critical per-poll T
# (recv-NI ack / UNI slot), which must never be starved. Sized = MAX_INFLIGHT - RTX_GAP_LIMIT_NI(2) - 1 (the
# T): with the window full of K, a host NI-handshake flood (one K per host frame) would otherwise crowd out
# the recv-NI ack the host waits on -> the NI handshake deadlocks (the latent hang).
K_INFLIGHT_MAX = 3
K_PER_VBLANK = 3           # max NEW K-acks queued per VBlank, leaving window slots for the per-VBlank 'T'
ACK_PERIOD = 2             # delayed-ack interval: a standalone bulk-ack is owed at most every ~33ms (2
                           # VBlanks). The ack piggybacks on a data datagram whenever one is being sent this
                           # VBlank and goes out standalone only when one is owed (received data / a gap to
                           # NACK) and the floor has elapsed. A faster ack frees the peer's send window
                           # sooner; the correct RTT-driven RTO keeps this from flooding the half-duplex link.
COMPRESS_MIN = 62          # zstd-compress an OUT datagram iff its message body is >= this many bytes - the
                           # EXACT rule the real Switch host uses (measured across the reference captures IN: largest raw=61,
                           # smallest compressed=62, zero overlap = a clean size threshold). Below it, frames
                           # go raw. Combined with crypto.ZSTD_LEVEL=4 this makes our wire BYTE-IDENTICAL to a
                           # real FRLG joiner. Small frames (single gba slot / ack ~16-37B) stay raw as on HW.

# The child 'T' timestamp (body[0:4], u32 LE) is a per-NEW-frame counter that must INCREASE per new
# frame and be REUSED on a Pia retransmit. The reference capture's child seeded it ~0x362e; the host
# appears to gate on monotonicity + rate, not an absolute base (uncertain on the live link), so we seed nonzero.
TS_SEED = 0x0000362E


class Sim:
    def __init__(self, transport, pia_crypto, engine, our_ip, host_ip, *, conn=None,
                 our_var=0xc493, compress=False, header_flags=0x50, capture_path=None,
                 linkstate=None, connect_id=None, log=lambda *a: None):
        self.t = transport
        self.crypto = pia_crypto
        self.engine = engine
        # Held-keys overworld link-state engine [frlgsim/linkstate.py]. When present, the sim emits a
        # 0xBE00 SEND_HELD_KEYS keepalive on an idle VBlank ONLY while engine.in_seat_phase (the
        # overworld/cable-seat phase, entry P0..P3) - mirroring SendKeysToRfu, which the real child
        # runs ONLY while gRfu.callback == SendKeysToRfu [link_rfu_2.c:1069-1080,1089]. That callback
        # is cleared the instant we warp out of the cable seat (Task_StartWirelessTrade case 0
        # ClearLinkRfuCallback() -> gRfu.callback = NULL [cable_club.c:918]), BEFORE the trade menu's
        # party exchange (BufferTradeParties [trade.c:935]) and the later gMain.callback1 =
        # CB1_UpdateLink swap [trade.c:1085]. So from the party exchange (S4) through the trade FSM and
        # the post-trade save an idle VBlank is a bare all-zero idle slot, NOT 0xBE00; held keys are
        # only re-armed back in the overworld field [field_fadetransition.c:226]. Held keys NEVER
        # override a real SEND_BLOCK/LINKCMD slot (we ask the engine first; held keys take an IDLE slot
        # only) - and engine.in_seat_phase latches off at the party exchange (entry.seat_phase_over).
        self.linkstate = linkstate
        self.conn = conn                # ConnectionManager (None = trade-only, e.g. replay)
        # LIVE (conn present): bound the engine's barrier standby burst per count so a never-completing
        # round can't flood the host (offline keeps the every-VBlank cadence its MockHost timing needs).
        if conn is not None and hasattr(engine, "barrier"):
            engine.barrier.max_emits = BARRIER_EMITS
        # LIVE: gate READY_TO_TRADE on the FULL BufferTradeParties (ribbons/settle) so we don't send it
        # mid-exchange (the offline MockHost model has no mail/ribbons, so this stays off there).
        if conn is not None and hasattr(engine, "_live"):
            engine._live = True
        self.our_ip = our_ip
        self.host_ip = host_ip
        self.broadcast = host_ip.rsplit(".", 1)[0] + ".255"
        self.compress = compress
        self.header_flags = header_flags
        self.log = log
        self.info = getattr(log, "info", log)   # clean milestone sink (default-mode narration)

        self.slot = rfu.SlotBuilder()
        # child 'T' frame counter (u32). One per NEW 'T' we emit; reused on a Pia retransmit (the
        # retransmit re-offers the already-built frame bytes, so ts is baked in at build time).
        self.ts = TS_SEED
        # emulator 'K' ack layer: the host sends a 'T' per VBlank; we owe exactly ONE 'K' per
        # UNIQUE host 'T' ts (k_seq global +1 from 1; host idle T (slot_len<=1) is acked too; the host
        # sends us NO K). `mid` (1-based position within the OUT Pia datagram) is assigned at flush.
        self._k_seq = 0                  # last k_seq used (next K is _k_seq+1)
        self._acked_ts = set()           # host T ts values already K-acked (dedup)
        self._pending_k = []             # [(k_seq, acked_ts)] queued, awaiting a datagram flush
        self._k_seqs = set()             # reliable seqs of OUR K-acks still in flight (for K_INFLIGHT_MAX)
        # NI sender machine: after the host accepts our 'C' (the 'A' frame), the child
        # runs the librfu NI sender to deliver its RfuGameData before any UNI trade traffic. Built
        # lazily once we know our identity (from the engine's LinkPlayer); None until the NI phase.
        self._ni = None
        self._ni_done = False
        self._ni_built = False
        # RECV-side NI: right after the host acks OUR send-NI it runs its OWN librfu NI
        # sender (its connection/join-status data). The child must ACK every host NI sub-frame (ack=1,
        # mirroring state/n/phase) or the host's NI transfer never completes and the host faults the
        # link ("Communication error"). We DISCARD the host's NI data content (no reassembly needed).
        self._ni_recv = ni.NIReceiver()
        # recv-NI ack dedup: we hold the ack for the host's CURRENT NI sub-frame and re-emit it once per
        # DISTINCT sub-frame (it updates when the host advances) - NOT a growing queue. An append-per-host-
        # frame queue spammed hundreds of duplicate acks when the host re-sent a sub-frame under loss
        # (observed: out NI_END x125); a single current-ack stays 1:1 with the host's sub-frames.
        self._cur_ni_ack = None          # slot bytes for the latest host NI sub-frame's recv-ACK
        # ONE recv-NI ack in flight per host sub-frame. The recv-NI ack is idempotent (the host needs only
        # its CURRENT sub-frame acked) - so we queue at most one reliable ack for it and let the reliable
        # layer retransmit that one under loss, instead of queuing a fresh ack every poll. Queuing one per
        # poll piles a backlog of stale acks; in-order delivery then delays the host's needed ack until the
        # backlog drains, so the host advances ever-slower and the NI handshake deadlocks (a latent race).
        self._ni_ack_seq = None          # reliable seq of the recv-NI ack currently in flight (or None)
        self._ni_ack_bytes = None        # the _cur_ni_ack bytes that seq carries (to detect a sub-frame change)
        self._emitted_ni_ack = None      # set by _gba_frame when it returns a recv-NI ack, so _drive_reliable records its seq
        self._host_uni_seen = False      # host sent its first UNI slot (state 4) => its NI is done -> UNI
        # recv-NI must go QUIET at the host's NI NULL (observed Communication-error). The host re-sends
        # NI_END until it sees our ack, THEN sends NULL; after NULL there is a ~2.4s join-textbox gap
        # before UNI where the reference capture sends ZERO 'T'. We were re-emitting the stale NI_END ack right through
        # that gap -> a malformed/out-of-protocol slot -> in-game "Communication error". Stop acking at
        # NULL: emit _cur_ni_ack only until NULL is seen, then K/bulk-acks only until _host_uni_seen.
        self._host_ni_null_seen = False
        self._ni_status_logged = False    # logged the host's recv-NI join status once
        self.ni_rejected = False          # host returned a non-JOIN_GROUP_OK status -> abort the trade
        self.host_disconnected = False    # host sent a emulator 'D' (0x44) disconnect -> link closing
        self.out_seq = RELIABLE_SEQ_START
        # Pia packet id: PER-CHANNEL counters keyed by Pia-header dst var-id (observed: the reference capture keeps THREE
        # independent pktid counters - dst=0x0000 establishing, dst=0x0001 session/RTT (1..960), dst=
        # host-var reliable/data (1..4415)). A single global counter SKIPPED reliable pktids once RTT/
        # Session interleaved, risking host-side drop/reorder of our reliable frames -> under-ack ->
        # BufferIsFull. Each channel starts at 1 and skips 0 on rollover; establishing frames force 0.
        self._pktid_by_dst = {}
        self.last_in_seq = 0
        self._recv_hi = None              # highest host reliable seq seen (wrap-aware) for the cumulative ack
        # Pia RELIABLE sliding-window connection. The peer ignores reliable DATA until we OPEN the stream
        # with an Initialized frame (the metadata/title frame); the two sides then bulk-ACK each other.
        # ReliableLink does the RETRANSMISSION (frames drop on this radio) + in-order delivery, with an
        # RTT-driven RTO and selective-repeat recovery. GAP-TARGETED retransmit (RTX_GAP_LIMIT, in
        # _drive_reliable) re-sends only the gap - the peer buffers out-of-order, so the gap alone drains
        # its run. Live only (conn!=None); offline replay/tests keep the bare path.
        self.rel = reliable.ReliableLink(start=RELIABLE_SEQ_START, max_inflight=MAX_INFLIGHT,
                                         rtt_jitter_k=RTT_JITTER_K, dup_nack_threshold=DUP_NACK_THRESHOLD,
                                         rto_ceil_ms=RTO_CEIL_MS, rto_backoff=RTO_BACKOFF,
                                         rto_bootstrap_ms=RTO_BOOTSTRAP_MS)
        self._rel_opened = False
        self._ack_owed = False           # received host reliable DATA we haven't bulk-acked yet
        self._last_ack_tick = -100       # last tick we emitted a ctrl bulk-ack (steady-cadence floor)
        self._tick = 0                   # VBlank counter, drives the retransmit timers
        # emulator RFU connect ('C') frame: our OWN 2-byte RFU connection id, self-chosen. Any nonzero
        # value works - the host does not match it, it just seats our slot - so a random nonzero id is
        # passed in. None (offline replay/tests) => we do NOT send a 'C' (the host stays bulk-ack-only
        # until it sees one).
        self._connect_id = bytes(connect_id) if connect_id else None
        self._gba_conn_sent = False
        self._gba_accepted = False        # have we seen the host's emulator connect accept ('A')
        # Emission is FREE-RUN: _drive_reliable emits one child slot ('T') per local VBlank, on our own
        # clock, NOT paced to the host's slot arrivals. The flood the host's receive side can't absorb is
        # bounded by the small send window (MAX_INFLIGHT), not by response pacing - so a steady one-per-
        # VBlank cadence keeps few frames in flight and keeps the host's poll loop fed across the NI->UNI
        # seam (a poll-paced child instead goes silent there and the host parks). _slot_credit still counts
        # host slots delivered but not yet responded to, but the free-run path resets it each VBlank and
        # does not gate emission on it (informational here).
        self._slot_credit = 0
        self._last_seat_emit = -100      # last tick we emitted a seat/leave held-keys (keepalive floor)
        self._seen_in = set()
        self.rx_count = self.tx_count = 0
        self.rx_fail = 0                 # host datagrams that failed to decrypt (SSID/key mismatch)
        self.rx_protos = {}              # proto id -> count of IN Pia messages seen
        self._dbg = None                 # set to a list to capture per-VBlank block-send emission decisions

        # our var id is SELF-CHOSEN and announced; the host's is LEARNED from incoming headers
        # (the host's first packet has dst=0 until it knows ours, so only src is reliable).
        self.our_var = our_var.to_bytes(2, "big")
        self.host_var = reliable.STATION_HOST.to_bytes(2, "big")
        self._learned = False
        # keep the ConnectionManager's self-chosen var id in sync with ours (it stores an int)
        if conn is not None:
            conn.our_var = int.from_bytes(self.our_var, "big")

        self._cap = open(capture_path, "w", buffering=1) if capture_path else None
        if self._cap:
            self._cap.write(json.dumps({"rec": "meta", "event": "session", "kind": "sim",
                                        "ip": our_ip, "host": host_ip,
                                        "ssid_hex": pia_crypto.ssid.hex(),
                                        "broadcast": self.broadcast}) + "\n")
        self._t0 = None

    @property
    def connected(self):
        return self.conn is None or self.conn.connected

    @property
    def _now_ms(self):
        """The VBlank counter as milliseconds - the clock the reliable layer runs on."""
        return self._tick * MS_PER_VBLANK

    # ---- capture -----------------------------------------------------------
    def _capture(self, direction, datagram, src, dst):
        if not self._cap:
            return
        if self._t0 is None:
            self._t0 = time.monotonic()
        self._cap.write(json.dumps({
            "rec": "pkt", "seq": self.rx_count + self.tx_count, "t": time.monotonic() - self._t0,
            "dir": direction, "proto": 17, "src": src, "dst": dst,
            "len": len(datagram), "hex": datagram.hex(),
        }) + "\n")

    # ---- RX ----------------------------------------------------------------
    def process_datagram(self, datagram, src_ip):
        if not cryptomod.is_pia(datagram):
            return False
        self._capture("in", datagram, f"{src_ip}:12345", f"{self.our_ip}:12345")
        hdr = cryptomod.PiaHeader.unpack(datagram)
        # Pia header is [dst_var][src_var]; the host announces its own var id as src.
        if not self._learned and hdr.src != 0:
            self.host_var = hdr.src.to_bytes(2, "big")
            self._learned = True
            if self.conn:
                self.conn.learn_ids(self.our_var, self.host_var)
        pt = self.crypto.decrypt(datagram, src_ip)
        if pt is None:
            self.rx_fail += 1
            if self.rx_fail <= 5:
                self.log(f"[sim] RX decrypt FAILED from {src_ip} hdr.src=0x{hdr.src:04x} "
                         f"(SSID/key mismatch?) - host msg never reaches the handshake")
            return False
        app, _ = cryptomod.decompress(pt)
        msgs, _, _ = reliable.parse_app(app)
        for m in msgs:
            self.rx_protos[m.proto] = self.rx_protos.get(m.proto, 0) + 1
        if self.rx_count < 8:
            self.log(f"[sim] RX ok from {src_ip}: protos={[m.proto for m in msgs]} "
                     f"(1=Net 3=RTT 10=Reliable 13=Session)")
        for m in msgs:
            if m.proto == reliable.PROTO_RELIABLE:
                rl = reliable.parse_reliable(m.payload)
                if rl is None:
                    continue
                if self.conn is None:                 # offline replay: feed frames as they arrive
                    self._note_in_seq(rl.seq)
                    if rl.flagsA & 0x01 and rl.payload[:1] == b"\x57":
                        self._on_gba_in(rl.payload)
                elif rl.flagsA & 0x01:                # live AppData: PROCESS AS IT ARRIVES (the emulator
                    # is order-tolerant - it reassembles blocks by fragment index and re-pulls), so we
                    # deliver each UNIQUE frame the instant it lands (never stall the synchronous RFU
                    # exchange on a gap). The PIA ACK is an honest selective-repeat ack: note_received tracks
                    # the contiguous recv_next + the out-of-order set, and ack_payload carries a selective
                    # MASK so the peer fast-retransmits exactly its drops.
                    self._ack_owed = True
                    if rl.seq not in self._seen_in:
                        self._note_in_seq(rl.seq)
                        if rl.payload[:1] == b"\x57":
                            self._on_gba_in(rl.payload)
                    self.rel.note_received(rl.seq)       # contiguous recv_next + recv_ooo for the selective ack
                else:                                 # live FLAGSA_CTRL: peer's bulk-ack of OUR sends
                    ackid, mask = reliable.parse_bulk_ack(rl.payload)
                    # frees acked frames (cumulative + selective mask); now_ms lets it sample the
                    # reliable round-trip (un-retransmitted frames) to drive the RTO.
                    self.rel.on_ack(ackid, mask, now_ms=self._now_ms)
            elif self.conn:
                self.conn.on_message(m.proto, m.payload, tick=self._tick)
        self.rx_count += 1
        return True

    def _on_gba_in(self, payload):
        """Dispatch one IN emulator frame (host/parent) by type.
          'A' (0x41): the host's emulator connect ACCEPT - the RFU link is up; arm the NI phase.
          'T' (0x54): a host slot frame. EVERY unique host T ts is K-acked (incl. idle slot_len<=1).
              UNI 'T' (the mpId rows) is fed to the trade engine; a host NI 'T' is the host's game-data
              handshake which our recv side must (eventually) ack - it is consumed here (its slots are
              not UNI, so the engine ignores them) and acked via the same per-ts K.
          'K' (0x4b): the host never sends us K, so this is informational only."""
        rec = gbaframe.parse_in(payload)
        if rec is None:
            return
        typ = rec.get("type")
        if typ == "A" and not self._gba_accepted:
            self._gba_accepted = True              # host's emulator connect ACCEPT (0x41)
            self.log(f"[sim] host ACCEPTED emulator connect ('A' 0x41): {payload[:10].hex()} "
                     f"-> our slot is seated; RFU link up, starting the NI handshake")
            self.info("Host accepted the link.")
            return
        if typ == gbaframe.TYPE_D and not self.host_disconnected:
            # host emulator DISCONNECT ('D' 0x44): the RFU link is going down. Surface it (a clean leave
            # signal) instead of silently ignoring it and spinning on a dead link.
            self.host_disconnected = True
            self.log("[sim] host emulator DISCONNECT ('D' 0x44) - RFU link closing")
            return
        if typ != "T":
            return
        # K-ack EVERY unique host T ts (one K per unique ts; host idle T is still acked).
        ts = rec.get("ts")
        if ts is not None and ts not in self._acked_ts:
            self._acked_ts.add(ts)
            self._k_seq += 1
            self._pending_k.append((self._k_seq, ts))
            if len(self._acked_ts) > 8192:         # bound memory on a long session
                self._acked_ts = set(list(self._acked_ts)[-2048:])
        # RECV-side NI: a host NI-window 'T' (NI_START/NI/NI_END/NULL, NOT UNI) carries record['ni'].
        # When it is the host's OWN outgoing NI (ack=0) enqueue a recv-NI ACK slot MIRRORING its
        # (state, n, phase) with ack=1, sz=0 (the host's NI data content is discarded). NIReceiver
        # marks the host's NI complete on the host NI_END (or NULL). This is ORTHOGONAL to the K layer
        # above (the host NI 'T' is still K-acked); the ack rides a SEPARATE child 'T' (see _gba_frame).
        ni_rec = rec.get("ni")
        if ni_rec is not None:
            ack_slot = self._ni_recv.on_host_ni(ni_rec)
            if ack_slot is not None:
                self._cur_ni_ack = ack_slot         # latest host NI sub-frame -> the ack to re-emit
            if ni_rec.get("state") == rfu.LCOM_NULL and ni_rec.get("ack") == 0:
                self._host_ni_null_seen = True       # host's NI terminator -> stop acking, go quiet
            # host join STATUS: log it once; a non-OK value means the host REJECTED us (full
            # lobby / blacklist / version mismatch), so flag it - else we'd ack forever then hang on a
            # UNI that never comes.
            st = self._ni_recv.status
            if st is not None and not self._ni_status_logged:
                self._ni_status_logged = True
                if st == ni.RFU_STATUS_JOIN_GROUP_OK:
                    self.log(f"[sim] host NI join status = JOIN_GROUP_OK ({st})")
                else:
                    self.ni_rejected = True
                    self.log(f"[sim] WARNING: host NI join status = {st} (NOT JOIN_GROUP_OK=5) -> host "
                             f"REJECTED our join; the trade cannot proceed")
        # The host's FIRST UNI slot (parent LLSF state 4) means its NI is finished and it has entered the
        # UNI trade phase -> our recv-NI is done. This is the transition trigger (it guarantees we never
        # send a UNI slot before the host itself is in UNI, which would fault its RFU link manager).
        if rec.get("llsf_state") == 4:
            self._host_uni_seen = True
        # Count every host 'T' (NI sub-frame, NI ack, UNI, or idle keepalive) as one delivered host slot.
        # _slot_credit tracks host slots delivered but not yet responded to; it is informational under the
        # free-run send path (which emits one child slot per VBlank and resets the credit each time), kept
        # so the counter stays meaningful if a poll-paced path is ever reintroduced.
        self._slot_credit += 1
        # Feed the host's UNI slots (the mpId gRecvCmds) to the trade engine; the parse_in record's
        # `positional` alias is exactly what the engine reads. A host idle/NI 'T' has no
        # UNI slots, so feed_in_frame is a no-op for it (it still got K-acked + counted as a tick).
        self.engine.feed_in_frame(rec)

    def _note_in_seq(self, seq):
        if seq in self._seen_in:
            return
        self._seen_in.add(seq)
        if len(self._seen_in) > 4096:
            self._seen_in = set(list(self._seen_in)[-1024:])
        if ((seq - self.last_in_seq) & 0xFFFF) < 0x8000:
            self.last_in_seq = seq

    # ---- TX ----------------------------------------------------------------
    def _next_pktid(self, dv):
        """Per-CHANNEL Pia packet id keyed by header dst var-id (observed: the reference capture keeps independent
        counters per dst - dst=0x0001 session/RTT (1..960), dst=host-var reliable/data (1..4415)).
        Each channel counts from 1, skipping 0 on rollover, so the reliable channel stays contiguous
        even when RTT/Session frames interleave on their own dst. The establishing connection-exchange
        frames (Net 0x12 / Session join) ride pktid 0 by passing pktid=0 explicitly to _send."""
        pktid = self._pktid_by_dst.get(dv, 1)
        self._pktid_by_dst[dv] = pktid + 1 if pktid < 0xFFFF else 1
        return pktid

    def _send_messages(self, messages, *, dst_var=None, src_var=None, compress=False,
                       footer=True, establishing=False, unicast=True, pktid=None, footer_var=None):
        """Frame N Pia messages into ONE datagram and send it (observed: the reference capture BATCHES up to 9 reliable
        messages per datagram; we used to emit one datagram per frame -> ~1.6x+ datagram flood ->
        host SEND-buffer overflow (BufferIsFull)]. `messages` = [(proto, payload), ...] sharing one
        header (same dst/src/pktid channel). The encrypted plaintext is:

            [ message* , optionally zstd-compressed AS A WHOLE ]
            [ footer: 2-byte recipient (destination) variable id, UNCOMPRESSED, only if footer ]
            [ 0xFF padding so the total is a multiple of 16 ]

        header byte5 = (padding_size << 4) | flags, flags = (1 if zstd) | (2 if establishing); the
        footer-size byte = len(footer). One pktid per datagram (per-channel), NOT per message."""
        if not messages:
            return None
        dv = dst_var if dst_var is not None else int.from_bytes(self.host_var, "big")
        sv = src_var if src_var is not None else int.from_bytes(self.our_var, "big")
        body = b"".join(reliable.build_message(m[0], m[1], m[2] if len(m) > 2 else None)
                        for m in messages)
        # zstd-compress like a real FRLG joiner: the host compresses iff the message body is >= 62 bytes
        # (COMPRESS_MIN), a pure size threshold. `compress=True` (the Session join) forces it regardless. At
        # crypto.ZSTD_LEVEL=4 + the window-frame header this is byte-identical to the console. Auto-compress
        # only when zstd is actually available (an explicit compress=True still raises if it isn't, as before).
        do_zstd = compress or (len(body) >= COMPRESS_MIN and cryptomod.HAVE_ZSTD)
        if do_zstd:
            body = cryptomod.compress(body)
        fsize = 0
        if footer:
            # footer = the RECIPIENT var id, which is usually the header dst, but for RTT the header dst
            # is the session pseudo-station 0x0001 while the recipient is still the host 0x7620.
            fv = footer_var if footer_var is not None else dv
            body += fv.to_bytes(2, "big")
            fsize = 2
        pad = (-len(body)) % 16                      # 0xFF-pad the whole body to a multiple of 16
        body += b"\xff" * pad
        flags = (1 if do_zstd else 0) | (2 if establishing else 0)
        if pktid is None:
            pktid = self._next_pktid(dv)
        hdr = cryptomod.PiaHeader(dst=dv, src=sv, pktid=pktid, nonce8=os.urandom(8),
                                  flags=(pad << 4) | flags, footer=fsize)
        dg = self.crypto.encrypt(body, self.our_ip, hdr)
        dst = self.host_ip if unicast else self.broadcast
        self.t.send(dg, dst)
        self._capture("out", dg, f"{self.our_ip}:12345", f"{dst}:12345")
        self.tx_count += 1
        return dg

    def _send(self, proto, payload, *, dst_var=None, src_var=None, compress=False,
              footer=True, establishing=False, unicast=True, pktid=None, footer_var=None):
        """Single-message convenience wrapper over _send_messages (one message per datagram) - used
        for the connection handshake / RTT / a lone reliable frame. The reliable STREAM batches via
        _send_messages directly (see _drive_reliable)."""
        return self._send_messages([(proto, payload)], dst_var=dst_var, src_var=src_var,
                                   compress=compress, footer=footer, establishing=establishing,
                                   unicast=unicast, pktid=pktid, footer_var=footer_var)

    # ---- Pia Reliable sliding-window connection -----------------------------
    def _tx_reliable(self, seq, flagsA, inner):
        """Wrap one inner payload in a Reliable(10) frame and send it. The header's "lowest pending
        ack" = our send-window left edge; pure-ack (FLAGSA_CTRL) frames carry no sequence id of
        their own, so they ride the window base seq (the reference capture reuses 0xFFF0)."""
        s = RELIABLE_SEQ_START if seq is None else seq
        rel = reliable.build_reliable(s, self.rel.send_low(), inner, flagsA=flagsA)
        self._send(reliable.PROTO_RELIABLE, rel,
                   dst_var=int.from_bytes(self.host_var, "big"),
                   src_var=int.from_bytes(self.our_var, "big"),
                   compress=False, footer=True, establishing=False)

    def _tx_reliable_batch(self, batch):
        """Send a list of reliable frames as FEW datagrams as possible (<=RELIABLE_BATCH_MAX messages
        each) (observed: the reference capture packs up to 9 Reliable messages per datagram - the prime BufferIsFull
        lever). `batch` = [(seq, flagsA, inner), ...] already in wire order (retransmits, K*, T,
        ctrl-ack). All ride the host channel (dst=host_var) so they share one per-channel pktid."""
        if not batch:
            return
        msgs = []
        for seq, flagsA, inner in batch:
            s = RELIABLE_SEQ_START if seq is None else seq
            rel = reliable.build_reliable(s, self.rel.send_low(), inner, flagsA=flagsA)
            # Pia MESSAGE-flags 0x40 on standalone acks. The native client AND the Switch host set 0x40 on
            # EVERY pure-ack (msgflags); we were the only party sending acks at msgflags=0. It's "unknown" in
            # kinnay's wiki but universal on acks - the host honored our CUMULATIVE ack at 0 (its window freed
            # early) yet never fast-retransmitted a hole, so 0x40 is almost certainly the bit that tells the
            # host to act on the ack's SELECTIVE mask (SACK / fast-retransmit). The ctrl-ack is LAST in the
            # batch so its 0x40 never leaks into a later message via msgflags inheritance. Data stays at 0.
            mf = 0x40 if flagsA == reliable.FLAGSA_CTRL else None
            msgs.append((reliable.PROTO_RELIABLE, rel, mf))
        dv = int.from_bytes(self.host_var, "big")
        sv = int.from_bytes(self.our_var, "big")
        for i in range(0, len(msgs), RELIABLE_BATCH_MAX):
            self._send_messages(msgs[i:i + RELIABLE_BATCH_MAX], dst_var=dv, src_var=sv,
                                compress=False, footer=True, establishing=False)

    def _drive_reliable(self):
        """Per-VBlank Reliable traffic once Pia-connected, loss-tolerant via ReliableLink:
          1. open the stream with the metadata frame (Initialized) - itself retransmitted until acked;
          2. RETRANSMIT any unacked frame whose timer expired (the dropped INIT/block/data frames);
          3. bulk-ack host data we've received (with a gap mask);
          4. send a new emulator frame, unless the in-flight window is full (let retransmits drain).
        Without the open frame the host never starts its Reliable stream; without retransmission a
        single dropped frame stalls the whole stream (frames are known to drop)."""
        tick = self._tick            # VBlank counter, for the ack/seat cadence floors
        now_ms = self._now_ms        # the reliable layer's millisecond clock (RTO timer)
        if not self._rel_opened:
            seq = self.rel.queue(reliable.METADATA_FRAME, reliable.FLAGSA_INIT, now_ms)
            self._tx_reliable(seq, reliable.FLAGSA_INIT, reliable.METADATA_FRAME)
            self._rel_opened = True
            return                        # the stream opens with the metadata ('J') frame alone
        if self._connect_id is not None and not self._gba_conn_sent:
            # emulator RFU connect request ('C') - the host won't send its accept ('A') or start its
            # slot ('T') stream until it sees this. `connect_id` is our self-chosen id; any nonzero
            # value works.
            frame = gbaframe.build_connect(self._connect_id)
            seq = self.rel.queue(frame, reliable.FLAGSA_GBA, now_ms)
            self._tx_reliable(seq, reliable.FLAGSA_GBA, frame)
            self._gba_conn_sent = True
            return
        # BATCH this VBlank's whole reliable output into ONE datagram (observed: the reference capture packs up to 9
        # messages/datagram; one-datagram-per-frame was the prime BufferIsFull cause). Wire order
        # (reference capture's dominant KT/KTA): retransmits, then new K* (mid 1..n), then the T slot, then the
        # ctrl-ack LAST. Everything shares the host channel so it rides one per-channel pktid.
        batch = []
        # 1. retransmits. BLOCK/TRADE phase: GAP-TARGETED (limit=RTX_GAP_LIMIT) - re-send only the oldest
        #    unacked frame (the cumulative gap); the host buffers out-of-order so delivering the gap drains
        #    its whole run. This kills the high-RTT Go-Back-N flood (re-sending the whole window on the
        #    ~440ms-2s-RTT bridge re-sent every frame many times before its ack -> flood -> latency climbs).
        #    NI/SEAT phase (low-volume, all frames critical): whole-window (limit=None, capped at the batch)
        #    so our few NI/standby frames get through fast - gap-targeting there starved the send-NI.
        #    due_retransmits returns the ORIGINAL bytes (a retransmitted K keeps its original mid).
        in_block_phase = self._gba_accepted and not getattr(self.engine, "in_seat_phase", True)
        rtx_limit = RTX_GAP_LIMIT if in_block_phase else RTX_GAP_LIMIT_NI   # never None
        for seq, flagsA, inner in self.rel.due_retransmits(now_ms, limit=rtx_limit)[:RELIABLE_BATCH_MAX]:
            batch.append((seq, flagsA, inner))
        # FREE-RUN emission: emit ONE new 'T' slot per VBlank on our OWN clock (not gated on how many host
        # polls arrived this tick), window-bounded, plus K-acks up to a small per-VBlank cap. _gba_frame()
        # returns the phase-correct slot (NI sub-frame / block fragment / trade slot / idle keepalive) or
        # None (recv-NI quiet / nothing to send), so one call per VBlank covers every phase. The flood guard
        # is the send window (max_inflight) + the RTT-driven gap-targeted retransmit, not response pacing.
        self._slot_credit = 0                         # consume any accumulated poll credits (unused here)
        # 2. K-acks FIRST (wire order K-then-T): one per pending host ts, capped at K_PER_VBLANK and the K
        #    in-flight cap, leaving window slots for the 'T'. _k_seqs tracks our unacked K so a K burst can
        #    never starve the critical per-poll T (recv-NI ack / UNI slot).
        self._k_seqs.intersection_update(self.rel.unacked)   # drop K seqs the host has acked (drained)
        mid = 0
        queued = 0
        k_frames = []
        for k_seq, acked_ts in self._pending_k:
            if self.rel.inflight() >= self.rel.max_inflight or queued >= K_PER_VBLANK:
                break                             # cap K/VBlank -> leave window slots for the block 'T'
            if len(self._k_seqs) >= K_INFLIGHT_MAX:
                break                             # K in-flight cap: leave the window for the T / recv-NI ack
            mid += 1
            kf = gbaframe.build_k(k_seq, mid, acked_ts)
            seq = self.rel.queue(kf, reliable.FLAGSA_GBA, now_ms)
            self._k_seqs.add(seq)
            k_frames.append((seq, reliable.FLAGSA_GBA, kf))
            queued += 1
        self._pending_k = self._pending_k[queued:][-K_BACKLOG_MAX:]
        # 3. our own 'T' slot - ONE per VBlank, ONLY after the host ACCEPTS our connect ('A'), window-bounded.
        t_frames = []
        if self._gba_accepted:
            _gated = self.rel.inflight() >= self.rel.max_inflight
            inner = None
            if not _gated:
                inner = self._gba_frame()
                if inner is not None:
                    self._last_seat_emit = tick
                    seq = self.rel.queue(inner, reliable.FLAGSA_GBA, now_ms)
                    t_frames.append((seq, reliable.FLAGSA_GBA, inner))
                    if self._emitted_ni_ack is not None:   # recv-NI ack just queued -> track the one in flight
                        self._ni_ack_seq = seq
                        self._ni_ack_bytes = self._emitted_ni_ack
            else:
                # WINDOW-GATED: cannot emit a new slot, but an in-flight block send must still advance
                # HOLD -> DONE on the host's reflection (arrives via IN frames, idempotent).
                self.engine.poll_send_done()
        # wire order is retransmits, K, T (the reference capture's KT pattern); the ctrl-ack goes last below.
        batch.extend(k_frames)
        batch.extend(t_frames)
        if self._gba_accepted and self._dbg is not None:   # per-VBlank emission trace (debug-only)
            _snd = getattr(self.engine, "sender", None)
            self._dbg.append({"tick": tick, "credits": 0, "kacks": queued,
                              "gba_emitted": len(t_frames), "inflight": self.rel.inflight(),
                              "sender": (_snd.state, _snd.index, _snd.count) if _snd else None})
        # 4. bulk-ack LAST (reference capture order K-T-A). Pure ack (FLAGSA_CTRL): carries recv_next (the contiguous gap)
        #    + the selective mask. RATE-LIMITED to ACK_PERIOD (~8.5/s, the real client's rate) and emitted ONLY
        #    when one is owed (received host data) or we have a gap to NACK - so it PIGGYBACKS on a data datagram
        #    when we're already sending one, and goes standalone only at the floor. (Root-cause fix, measured:
        #    the old `if batch or _ack_owed or due` emitted a STANDALONE pure-ack datagram nearly every VBlank
        #    (~30/s, 95% of OUT datagrams) -> half-duplex flood -> host->us return collapsed to ~9/s -> send->ack
        #    RTT 1.8s vs the real client's 24ms on the SAME bridge -> 6-frame window pushed ~3/s -> block crawl.)
        due = (tick - self._last_ack_tick) >= ACK_PERIOD
        if due and (self._ack_owed or self.rel.recv_ooo):
            batch.append((None, reliable.FLAGSA_CTRL, self.rel.ack_payload()))
            self._ack_owed = False
            self._last_ack_tick = tick
        self._tx_reliable_batch(batch)

    def _ensure_ni(self):
        """Build the NI sender once we have an identity (after the host accepts our 'C'). The 26-byte
        NI src is the child's RfuGameData connection config, CONSTRUCTED from our sim identity (the
        engine's LinkPlayer: version, public OT id, OT name) - not hardcoded reference-capture bytes."""
        if self._ni_built:
            return
        self._ni_built = True
        lp = getattr(self.engine, "lp", None) or linkplayer.LinkPlayer()
        src = ni.build_game_data(version_low=lp.version & 0xFF,
                                 trainer_id=lp.trainer_id & 0xFFFF, ot_name=lp.name)
        self._ni = ni.NISender(src)

    def _gba_frame(self):
        """Build this VBlank's emulator 'T' (0x54) frame, emitting ONE slot:

          1. NI handshake (after the host's 'A', BEFORE any UNI): drive the librfu NI sender one
             sub-frame per VBlank (game-data delivery) until it is exhausted.
          2. UNI trade slot: rfu.uni_slot(SlotBuilder.build(engine.tick())) wrapped in the child UNI
             LLSF - the trade engine's work, an all-zero IDLE slot, or (in the overworld/SEAT phase,
             ONLY AFTER establishment) a 0xBE00 held-keys keepalive.

        The held-keys gate is the C2 fix: held keys + sit() fire ONLY while engine.established
        (gReceivedRemoteLinkPlayers: both LinkPlayer blocks exchanged) AND engine.in_seat_phase (still
        in the overworld/cable seat, before the trade menu). Pre-establishment idle VBlanks are bare
        all-zero IDLE slots (tag untouched), so our tagged 0xBE00 never races ahead of the NI/block
        handshake and faults the host's childSendCmdId check. Held keys never override a real
        block/LINKCMD slot (we ask the engine first; held keys take an IDLE slot only).

        The ts (body[0:4]) is the per-NEW-frame u32 counter (+1 per new T; reused on retransmit, which
        re-offers the already-built bytes). Single slot per frame, one frame per VBlank (free-run)."""
        self._emitted_ni_ack = None      # cleared each call; set only when this call returns a recv-NI ack
        # NI handshake first (only while connected to the host's RFU, before steady UNI). The post-'A'
        # order is: our SEND-NI (game data) -> recv-NI (ack the host's own NI) -> UNI. We do NOT go UNI
        # until BOTH our send-NI is finished AND the host itself has entered UNI (its first state-4 poll);
        # going UNI early races a UNI slot ahead of the host's still-open NI sender and faults the link.
        if self.conn is not None and self._gba_accepted and not self._ni_done:
            self._ensure_ni()
            # 1. drive our send-NI to completion first (one sub-frame per VBlank). Single pass - Pia
            #    Reliable guarantees delivery+order under us, so we don't stop-and-wait.
            if not self._ni.done:
                slot = self._ni.next_slot()
                if slot is not None:
                    return self._wrap_t(slot)
            # 2. emit the recv-NI ack once per DISTINCT host sub-frame (idempotent; the reliable layer
            #    retransmits it under loss, so there is no need to re-queue it every poll).
            if self._cur_ni_ack is not None and self._ni_ack_bytes != self._cur_ni_ack:
                self._emitted_ni_ack = self._cur_ni_ack
                return self._wrap_t(self._cur_ni_ack)
            # 3. switch to UNI only once the host itself has entered UNI (_host_uni_seen); switching earlier
            #    sends a state-4 slot into the host's still-open NI sender -> the in-game Communication error.
            if not self._host_uni_seen:
                return None
            self._ni_done = True
            self.log("[sim] host entered UNI -> NI handshake complete, switching to UNI trade slots")
            self.info("Join handshake complete.")

        # engine.tick() returns the 7-int slot, OR None on a barrier frame whose want_emit() has
        # nothing to emit this VBlank (e.g. the post-trade save chain idling between echoes). None == an
        # IDLE slot here, so coerce to [0]*7 rather than crashing on words[0] (observed: post-commit crash).
        words = self.engine.tick() or [0] * 7
        if (self.linkstate is not None and (words[0] & 0xFFFF) == 0
                and getattr(self.engine, "established", False)
                and getattr(self.engine, "host_in_seat", False)
                and getattr(self.engine, "in_seat_phase", True)):
            # held-keys keepalive + sit, ONLY once the host is at its seat (host_in_seat) AND we are still
            # in the seat phase (before the party exchange latches seat_phase_over) (seat-barrier).
            words = self.linkstate.tick()
        cmd14 = self.slot.build(words)
        return self._wrap_t(rfu.uni_slot(cmd14))

    def _wrap_t(self, slot):
        """Wrap one complete slot (NI sub-frame or rfu.uni_slot(...)) in a child 'T' frame with the
        next u32 ts, advancing the counter (+1 per NEW frame)."""
        frame = gbaframe.wrap_t(slot, self.ts)
        self.ts = (self.ts + 1) & 0xFFFFFFFF
        return frame

    def _reliable_trade_payload(self):
        """Offline (conn=None) path: build ONE Reliable frame carrying this VBlank's gba 'T'. The K-ack
        layer / NI handshake are live-only (driven by the host's RFU which the offline ReplayTransport
        does not provide an 'A' for), so this stays the bare UNI/idle 'T' the offline tests expect."""
        frame = self._gba_frame()
        rel = reliable.build_reliable(self.out_seq, self.last_in_seq, frame)
        self.out_seq = (self.out_seq + 1) & 0xFFFF
        return rel

    # ---- one VBlank --------------------------------------------------------
    def tick(self):
        self._tick += 1                  # drives the ReliableLink retransmit timers
        for datagram, src_ip in self.t.recv():
            self.process_datagram(datagram, src_ip)
        # Supplementary RTT source: feed any round-trips the RTT protocol measured into the reliable RTO
        # (median of the last 7), converting VBlanks->ms. Over this link the host doesn't echo our RTT
        # systime, so this is usually empty and the reliable layer's own clean-ack round-trip is what
        # actually drives the RTO; if a host does echo it, these samples fold into the same median.
        if self.conn is not None and getattr(self.conn, "rtt_samples", None):
            for rtt_vblanks in self.conn.rtt_samples:
                self.rel.add_rtt_sample(rtt_vblanks * MS_PER_VBLANK)
            self.conn.rtt_samples = []
        # S0 handshake + RTT replies; each outbox entry is a dict carrying its own stage var-ids and
        # Pia framing (compress/footer/establishing) [pia_connect].
        if self.conn:
            if hasattr(self.conn, "maybe_originate_rtt"):
                self.conn.maybe_originate_rtt(self._tick)   # liveness RTT probe (dst=0x0001)
            for e in self.conn.drain():
                self._send(e["proto"], e["payload"], dst_var=e["dst"], src_var=e["src"],
                           compress=e["compress"], footer=e["footer"],
                           establishing=e["establishing"], unicast=e.get("unicast", True),
                           pktid=e.get("pktid"), footer_var=e.get("footer_var"))
        # Reliable traffic only once the Pia connection is up. Live (conn present): drive the full
        # sliding-window connection (open stream + bulk-acks + gba frame) so the host engages its
        # own Reliable stream. Offline replay/tests (conn=None): emit the bare gba frame as before.
        if self.connected:
            if self.conn is not None:
                self._drive_reliable()
            else:
                self._send(reliable.PROTO_RELIABLE, self._reliable_trade_payload(),
                           dst_var=int.from_bytes(self.host_var, "big"),
                           src_var=int.from_bytes(self.our_var, "big"),
                           compress=False, footer=True, establishing=False)

    def close(self):
        if self._cap:
            self._cap.close()
