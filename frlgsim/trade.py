"""The JOINER trade FSM - reacts to host verdicts, drives the block sub-FSM.

The sim is a reactive Follower: it stages blocks, supplies them when the Leader pulls with
SEND_BLOCK_REQ (host-SIZED), pushes its own 20-byte LINKCMD blocks, and REACTS to the Leader's
broadcasts (SET_MONS -> START -> CONFIRM_FINISH). It never emits SET_MONS/START/CONFIRM/cancel
broadcasts [trade.c:1637-1666].

Block supply is keyed by the REQ size + phase (robust to whether the host pulls a trainer card):
  200 first -> LinkPlayerBlock(60B in a 200B buffer)   then -> party blocks #1/#2/#3 (gPlayerParty)
  100 -> trainer card    220 -> mail    40 -> giftRibbons
The host's selected mon (received in the party blocks, indexed by the SET_MONS cursor) is what
we receive; it is saved as a .pk3 when CONFIRM_FINISH_TRADE commits the trade.
"""

from . import block, mon as monmod, linkplayer, rfu, barrier as barriermod

# LINKCMD opcodes (ride as word0 of a 20-byte/count=2 block).
READY_TO_TRADE = 0xAABB         # OUT
SET_MONS_TO_TRADE = 0xDDDD      # IN
INIT_BLOCK = 0xBBBB             # OUT (confirm-YES)
START_TRADE = 0xCCDD            # IN
READY_FINISH_TRADE = 0xABCD     # OUT
CONFIRM_FINISH_TRADE = 0xDCBA   # IN
REQUEST_CANCEL = 0xEEAA         # OUT
READY_CANCEL_TRADE = 0xBBCC     # OUT
PLAYER_CANCEL_TRADE = 0xDDEE    # IN
BOTH_CANCEL_TRADE = 0xEEBB      # IN
PARTNER_CANCEL_TRADE = 0xEECC   # IN
LINKCMD_NAMES = {v: k for k, v in dict(
    READY_TO_TRADE=READY_TO_TRADE, SET_MONS_TO_TRADE=SET_MONS_TO_TRADE, INIT_BLOCK=INIT_BLOCK,
    START_TRADE=START_TRADE, READY_FINISH_TRADE=READY_FINISH_TRADE,
    CONFIRM_FINISH_TRADE=CONFIRM_FINISH_TRADE, REQUEST_CANCEL=REQUEST_CANCEL,
    READY_CANCEL_TRADE=READY_CANCEL_TRADE, PLAYER_CANCEL_TRADE=PLAYER_CANCEL_TRADE,
    BOTH_CANCEL_TRADE=BOTH_CANCEL_TRADE, PARTNER_CANCEL_TRADE=PARTNER_CANCEL_TRADE).items()}

PARTY_SIZE = 6
# Block counts (= ceil(size/12)) used to classify a completed peer-0 block.
COUNT_LINKCMD = 2
COUNT_PARTY = 17
COUNT_MAIL = 19         # host mail block: 208B payload (PARTY_SIZE*sizeof(Mail=34)+4) in the fixed 220B buffer -> ceil(220/12)
COUNT_RIBBON = 4        # host giftRibbons block: 11B payload (giftRibbons[11]) in the fixed 40B buffer -> ceil(40/12)

# CheckValidityOfTradeMons return values [include/constants/trade.h:31-34].
PLAYER_MON_INVALID = 0          # our selected mon is the last alive mon
BOTH_MONS_VALID = 1
PARTNER_MON_INVALID = 2         # host offered an (illegitimate) Deoxys/Mew

# Illegitimate-only species the host may refuse to trade [trade.c:1966; species.h:155,419].
# CheckValidityOfTradeMons returns PARTNER_MON_INVALID for a Deoxys/Mew WITHOUT the modern
# fateful-encounter flag. Our carver cannot decode that flag (live residual), so the sim treats
# any offered Deoxys/Mew as the PARTNER_MON_INVALID trigger when configured to.
SPECIES_MEW = 151
SPECIES_DEOXYS = 410

# DoTradeAnim_Wireless duration stand-in. The wireless link-trade animation is a long
# multi-state sequence (STATE_TAKE_CARE_OF_MON 250f trade_scene.c:1749-1759, STATE_BYE_BYE 80f
# 1851-1852, STATE_GBA_FLASH 20+f 1907-1908, STATE_DELAY_FOR_MON_ANIM/AFTER_NEW_MON_DELAY 60f each
# 1736-1737/1761-1762, plus several palette-fade + slide states), ending at STATE_END_LINK_TRADE
# which returns TRUE for a link trade (1769-1771). Wire-anchored START_TRADE(t329.5s) ->
# READY_FINISH(t361.9s) = 32.4s ~= 1935 frames @ 59.727Hz. Content-dependent (species cries /
# evolution prompts shift it), so this is a stand-in, not exact - the early-arrival guard below
# makes the FSM correct for ANY value; only the cosmetic alignment needs the live Switch.
DEFAULT_ANIM_FRAMES = 1935

# The 180-frame QueueAction(180, QUEUE_SEND_DATA) delay before READY_CANCEL_TRADE on an
# invalid-mon verdict [trade.c:1989/2000].
INVALID_CANCEL_DELAY = 180

# FSM states (for logging/tests).
S1_LINK, S4_PARTY, S5_SELECT, S6_CONFIRM, S7_ANIM, S8_DONE, S_CANCEL = \
    "S1_LINK", "S4_PARTY", "S5_SELECT", "S6_CONFIRM", "S7_ANIM", "S8_DONE", "S_CANCEL"

# CHILD-INITIATED standby points [link_rfu_2.c:1566-1573]: the child reaches the SAME
# trade.c / trade_scene.c state the host does and calls SetLinkStandbyCallback() ITSELF. The engine
# INITIATEs a barrier at each (so a strict-ROM host parked in Rfu_LinkStandby's leader branch, which
# WAITS for the child, is unblocked):
#   (a) trade-menu entry  [trade.c:914-915]  - soft initiate (selection not stalled), in tick()
#   (b) menu->scene seam  [trade.c:2159-2166]- soft initiate (anim not stalled), in tick()
#   (c) post-trade save chain [trade_scene.c:2566-2725] - QUIESCENT chain, _run_save_chain()
#   (d) cancel-exit       [trade.c:2117-2132]- QUIESCENT, _cancel_barrier_active, on BOTH_CANCEL

# BLOCK_REQ_* reqtype selectors [include/link.h:111-115]. The host puts one in word0's low byte of a
# SEND_BLOCK_REQ slot; it indexes sBlockRequests[] to size OUR reply block [link.c:185-190;
# link_rfu_2.c:1172-1173]. reqtype 2 = BLOCK_REQ_SIZE_100 = the trainer card.
BLOCK_REQ_SIZE_NONE = 0     # identical to 200
BLOCK_REQ_SIZE_200 = 1      # LinkPlayer / party blocks
BLOCK_REQ_SIZE_100 = 2      # trainer card (Task_ExchangeCards entry pull)
BLOCK_REQ_SIZE_220 = 3      # mail
BLOCK_REQ_SIZE_40 = 4       # giftRibbons
REQ_SIZE = {BLOCK_REQ_SIZE_NONE: 200, BLOCK_REQ_SIZE_200: 200, BLOCK_REQ_SIZE_100: 100,
            BLOCK_REQ_SIZE_220: 220, BLOCK_REQ_SIZE_40: 40}

# WARP-QUIESCE standby burst size (fixes a black-screen-at-warp regression). The host gates the card
# pull / the seat on seeing our READY_EXIT_STANDBY, but it wants a BOUNDED handshake burst, not a
# continuous stream. The reference capture's guest emits count=0 only ~4x then idles (host pulls the
# card ~1s later); our old logic emitted it EVERY VBlank until card_supplied, so when the host was slow
# to pull (one run: 7s) we flooded ~247 standby frames, JAMMED the reliable window (max_inflight unacked)
# and could not send the card when finally pulled -> desync -> black screen. Cap the NEW emits per round;
# reliable retransmit (re-sends the queued burst until acked) guarantees delivery even under loss, so a
# small bounded burst is robust. 6 = the reference capture's ~4 plus a small loss margin.
WARP_STANDBY_EMITS = 6

# Post-seat warp into the trade SCENE (fixes a black screen after both players sit). Reference capture:
# after BOTH players sit (READY), the guest emits TWO more standby rounds - READY_EXIT_STANDBY count=2
# then count=3 - and only THEN does the host pull the party (BufferTradeParties, REQ size 200). There are
# FOUR standby rounds total (0 post-LinkPlayer, 1 post-card, 2+3 post-seat). We were emitting only 0 and 1, so after the seat
# the host waited for count=2/3 that never came -> black screen. POST_SEAT_STANDBY_DELAY ticks of held-keys
# keepalive run first so our READY (sit) actually goes out before we switch the slot to the standby.
POST_SEAT_STANDBY_DELAY = 20

# The post-seat standby is a MUTUAL barrier: advance count=2 -> count=3 ONLY after the host has reached
# count=2 (its own mp0 0x6600 count=2, latched in barrier.host_count). The native-Pia reference capture
# advances each standby count
# strictly after the host acks the current one (out N -> in mp0 N -> out N+1). Bursting count=3 before the
# host finished count=2 desyncs its readyExitStandby FSM -> in-game "Communication error" (intermittent,
# RTT-dependent) (observed as a comms error in a live run). WARP4_WATCHDOG is the
# OFFLINE / non-participating-host backstop: if the host never broadcasts count=2 within this many VBlanks
# of us finishing the count=2 burst, advance anyway (set well above any real RTT so a live host always
# reaches count=2 first - the reactive gate, not the watchdog, drives the live path).
WARP4_WATCHDOG = 180

# Inter-round pace for the post-trade SAVE barrier chain [trade_scene.c:2566-2725, CB2_SaveAndEndTrade].
# The host paces each save SetLinkStandbyCallback by its REAL save (LinkFullSave_WriteSector + the case-40
# random delay): on the native-Pia reference capture the post-CONFIRM standby counts land ~0.3-1.8s apart (avg ~70 frames). We have no
# real save, so completing one round (host echoed our count) and IMMEDIATELY bursting the next races the
# standby count ahead of the host's save FSM -> desync -> host stuck saving -> in-game comms error (observed in a live run).
# We instead wait SAVE_BARRIER_GAP frames between rounds (the FIRST round stays prompt - its host-side wait
# [case 100] has a 180f timeout; the later rounds [cases 42/44/6] have NO timeout, so being slower is safe).
SAVE_BARRIER_GAP = 60

# Dead-host safety net for the post-trade save chain. The host pauses up to ~1.8s between save barriers
# (its real LinkFullSave writes), so the chain must NOT end on a short quiet window - it ends when the host
# RE-EXCHANGES (Phase M, host_reexchange in feed_in_frame). This timeout only releases a truly vanished host
# (well above any real inter-barrier pause) so the sim never hangs forever.
SAVE_CHAIN_TIMEOUT = 600

# Frames of host block-inactivity before we treat BufferTradeParties as finished WITHOUT having seen the
# ribbons block [READY_TO_TRADE / cancel-to-leave gate, last-resort fallback]. The LIVE host ALWAYS
# streams mail+ribbons and the reliable layer delivers them, so _got_ribbons normally fires; this fallback
# only exists to avoid hanging on a genuinely dead host. It must be well above any real host pause: the
# host's post-trade save-writes stall it 0.3-1.8s between block pulls, and firing during such a pause sends
# the cancel-to-leave BEFORE the host's mail/ribbons - exactly the deadlock the gate is meant to avoid (the
# host then waits for our select mid-BufferTradeParties while we wait for BOTH_CANCEL). 220f (~3.7s) was
# close enough to a real pause to false-trigger; 600f (~10s) matches the dead-host SAVE_CHAIN_TIMEOUT
# philosophy - long enough that only a truly vanished host trips it.
BUFFERTRADE_SETTLE = 600

# Block counts (= ceil(size/12)) for the entry-phase trainer card: 100B -> 9 fragments.
COUNT_TRAINER_CARD = 9      # ceil(100/12)

# Union-room -> trade-center ENTRY phases (P0..P5) [decomp chain below]. These
# precede the sim's S1 (Task_PlayerExchange) and run ONCE per session (NOT re-fired on trades 2..6 -
# the post-trade loop returns to CB2_StartCreateTradeMenu, NOT back through the seat barrier
# [trade_scene.c:2752; trade.c:1320]). The two standby windows (P0/P3) are answered reactively by the
# BarrierResponder; the seat held-keys barrier (P2) is driven by linkstate.py; the card pull (P1) is
# supplied REQ-driven here. P5 is the handoff into the existing S1 entry edge.
#   P0 WARP_QUIESCE_1 Task_RunScriptAndFadeToActivity case2/3: SetLinkStandbyCallback +
#                     IsLinkTaskFinished [union_room.c:1975-2013] (STANDBY WINDOW #1) -> quiescent.
#   P1 CARD_EXCHANGE  Task_ExchangeCards: host (mpId 0) SendBlockRequest(BLOCK_REQ_SIZE_100); the
#                     RFUCMD_SEND_BLOCK_REQ pulls OUR 100B trainer card, and we receive the host's
#                     [union_room.c:1753-1789,1843-1855,1929-1933; link_rfu_2.c:1172-1173].
#   P2 SEAT_BARRIER   Task_EnterCableClubSeat: held-keys LINK_KEY_CODE_READY(0x16) in a 0xBE00 slot
#                     -> GetCableClubPartnersReady CABLE_SEAT_SUCCESS [cable_club.c:827-868;
#                     overworld.c:2951-3000] (linkstate.py; live residual).
#   P3 WARP_QUIESCE_2 Task_StartWirelessTrade case2/3: SetLinkStandbyCallback + IsLinkTaskFinished
#                     [cable_club.c:910-942] (STANDBY WINDOW #2) -> quiescent.
#   P4 TRADE_MENU     CB2_CreateTradeMenu -> the trade menu / S1 party exchange begins [trade.c:826].
#   P5 IN_TRADE       the trade FSM (S1..S8) owns the link; entry is complete and one-shot.
P0_WARP_QUIESCE_1 = "P0_WARP_QUIESCE_1"
P1_CARD_EXCHANGE = "P1_CARD_EXCHANGE"
P2_SEAT_BARRIER = "P2_SEAT_BARRIER"
P3_WARP_QUIESCE_2 = "P3_WARP_QUIESCE_2"
P4_TRADE_MENU = "P4_TRADE_MENU"
P5_IN_TRADE = "P5_IN_TRADE"
ENTRY_PHASES = (P0_WARP_QUIESCE_1, P1_CARD_EXCHANGE, P2_SEAT_BARRIER,
                P3_WARP_QUIESCE_2, P4_TRADE_MENU, P5_IN_TRADE)

# Leader-only broadcast opcodes the Follower must NEVER emit [trade.c:1637-1672,1681+]. Used by the
# seat-side invariant: a mpId==1 Follower only reacts to these, the Leader (mpId==0) emits them.
LEADER_BROADCAST_OPCODES = frozenset((
    SET_MONS_TO_TRADE, START_TRADE, CONFIRM_FINISH_TRADE,
    PLAYER_CANCEL_TRADE, BOTH_CANCEL_TRADE, PARTNER_CANCEL_TRADE))


def linkcmd_block(cmd, cursor=0):
    """Build the 20-byte LINKCMD action block: linkData[0]=cmd, linkData[1]=cursor, rest 0."""
    return (cmd & 0xFFFF).to_bytes(2, "little") + (cursor & 0xFFFF).to_bytes(2, "little") \
        + b"\x00" * 16


def resolve_offered_slots(offered_slots, trade_slot, trades, party_size=None):
    """Per-round distinct offered-slot list (len==trades), the OUR-party indices to give away one
    per round. Explicit `offered_slots` is validated (len==trades, distinct,
    non-negative); when omitted it derives an ascending distinct list seeded at trade_slot:
    [trade_slot, trade_slot+1, ...] (so trades==1 => [trade_slot], the back-compat default). If that
    seeded list would overflow the party (e.g. trade_slot=1 default with trades=6), it falls back to
    [0, 1, ..., trades-1] (the full-party-swap default). The list MUST be distinct because TradeMons
    SWAPs the received mon into the offered slot (trade_scene.c:1054-1083), so re-offering a slot
    would re-give a just-received mon."""
    if offered_slots is not None:
        slots = list(offered_slots)
        if len(slots) != trades:
            raise ValueError(f"offered_slots must have {trades} entries, got {len(slots)}")
        if any(s < 0 for s in slots):
            raise ValueError(f"offered_slots must be non-negative, got {slots}")
        if len(set(slots)) != len(slots):
            raise ValueError(f"offered_slots must be distinct (no slot re-offered), got {slots}")
        return slots
    seeded = [trade_slot + i for i in range(trades)]
    if party_size is not None and any(s >= party_size for s in seeded):
        return list(range(trades))      # full-party-swap default (trade_slot left default)
    return seeded


class EntryPhase:
    """Tracks the union-room -> trade-center ENTRY (P0..P5) as a ONE-SHOT, wire-observable progression.
    It does NOT generate the standby/seat traffic itself (the BarrierResponder and
    linkstate.py do that, reactively/keepalive); it RECORDS the deterministic ordering so the offline
    tests can assert: (a) the card pull (P1) precedes the trade menu / first READY_TO_TRADE; (b) the
    entry is complete (advanced to P5) before the trade dance; and (c) it is one-shot (never re-fires
    on trades 2..6 - the post-trade loop re-enters CB2_StartCreateTradeMenu, not the seat barrier).

    Phase advance is monotonic (a phase can only move forward) and driven by wire facts the engine
    already decodes:
      * a host BLOCK_REQ_SIZE_100 pull or a received 100B (count=9) card block -> reach P1.
      * the first SET_MONS / the first party-block completion / the first OUT READY_TO_TRADE means the
        trade menu is live -> reach P4/P5 (the seat barrier P2 + standby P3 are already behind us).
    The card supplier is REQ-driven (live residual: the live host may or may not issue the pull),
    so P1 is only RECORDED if it is actually observed - the progression tolerates the pull being
    absent (it then advances straight to P4/P5 when the trade menu opens)."""

    def __init__(self, log=lambda *a: None):
        self.phase = P0_WARP_QUIESCE_1
        self.phase_history = [P0_WARP_QUIESCE_1]
        self.card_pulled = False        # host issued a BLOCK_REQ_SIZE_100 (we were pulled for a card)
        self.card_supplied = False      # we staged/streamed our 100B card in reply
        self.host_card = None           # the host's 100B trainer card (count=9 block), if received
        # seat_phase_over latches at P4 (the trade menu opens / the party exchange begins). It is the
        # decomp-faithful held-keys CUTOFF: Task_StartWirelessTrade case 0 calls ClearLinkRfuCallback()
        # [cable_club.c:918], setting gRfu.callback = NULL, BEFORE the trade menu (CB2_CreateTradeMenu)
        # and its party exchange (BufferTradeParties, case 6 [trade.c:935]). So SendKeysToRfu (the
        # 0xBE00 emitter) stops the instant we warp out of the cable seat - i.e. by the time ANY trade
        # /party traffic is on the wire. This latches strictly EARLIER than `complete` (P5, the first
        # mon selection), so held keys are correctly OFF throughout S1_LINK and the S4 party exchange.
        self.seat_phase_over = False
        self.complete = False           # advanced to P5: entry done, trade FSM owns the link
        self.log = log
        self.info = getattr(log, "info", log)   # clean milestone sink (default-mode narration)

    def _advance_to(self, phase):
        """Monotonic forward-only phase advance (records each NEW phase, collapses repeats)."""
        if ENTRY_PHASES.index(phase) <= ENTRY_PHASES.index(self.phase):
            return
        # record every intermediate phase so the ordering history is complete even on a jump (e.g.
        # the card pull is skipped and the trade menu opens directly).
        cur = ENTRY_PHASES.index(self.phase)
        for p in ENTRY_PHASES[cur + 1:ENTRY_PHASES.index(phase) + 1]:
            self.phase = p
            self.phase_history.append(p)
            self.log(f"entry: -> {p}")
        # P4 (and anything past it) means we have warped out of the cable seat: Task_StartWirelessTrade
        # already cleared the keys callback [cable_club.c:918] before CB2_CreateTradeMenu ran, so the
        # held-keys keepalive is off from here on (the held-keys CUTOFF, NOT P5).
        if ENTRY_PHASES.index(phase) >= ENTRY_PHASES.index(P4_TRADE_MENU):
            self.seat_phase_over = True
        if phase == P5_IN_TRADE:
            self.complete = True

    def on_card_req(self):
        """The host pulled our trainer card (BLOCK_REQ_SIZE_100). One-shot: only meaningful before the
        trade menu opens (a later 100B pull, were one to occur, is ignored once complete)."""
        if self.complete:
            return
        if not self.card_pulled:
            self.card_pulled = True
            self.log("entry: host pulled BLOCK_REQ_SIZE_100 (trainer card)")
        self._advance_to(P1_CARD_EXCHANGE)

    def on_card_supplied(self):
        if not self.complete:
            self.card_supplied = True

    def on_host_card(self, data100):
        """Consume the host's 100B trainer card (count=9 block) into recvBuffer[0]-equivalent storage,
        WITHOUT advancing the trade FSM (Task_ExchangeCards CopyTrainerCardData is cosmetic
        [union_room.c:1769-1779])."""
        if self.complete:
            return
        self.host_card = bytes(data100[:100])
        self._advance_to(P1_CARD_EXCHANGE)
        self.log("entry: received host trainer card (100B) -> recvBuffer[0]")
        self.info("Exchanged trainer cards.")

    def on_seat_reached(self):
        """The host reached its cable-club seat (first SEND_HELD_KEYS). We are now in the SEAT BARRIER
        (P2): the standby#1 + card + standby#2 are behind us. This is when our held-keys/sit (READY 0x16)
        may fire. Does NOT latch seat_phase_over (that is P4, the party exchange)."""
        if not self.complete:
            self._advance_to(P2_SEAT_BARRIER)

    def on_trade_menu_open(self):
        """The trade menu has OPENED and the party exchange has begun (the FIRST party/LinkPlayer
        block is on the wire). This is strictly AFTER Task_StartWirelessTrade cleared the keys
        callback [cable_club.c:918] and CB2_CreateTradeMenu started BufferTradeParties [trade.c:935],
        so the held-keys keepalive is already off. Advance to P4 (TRADE_MENU) - this latches
        seat_phase_over WITHOUT yet completing the entry (P5 is the first mon selection)."""
        self._advance_to(P4_TRADE_MENU)

    def on_trade_menu_live(self):
        """The first mon selection is happening: the seat barrier (P2), standby window #2 (P3) and the
        party exchange (P4) are behind us; mark entry complete (P5) and hand off to the trade FSM."""
        self._advance_to(P5_IN_TRADE)


class TradeEngine:
    def __init__(self, party, trade_slot=1, link_player=None,
                 anim_delay=None, mpid=1, decline=False, refuse_partner_deoxys_mew=False,
                 trades=1, offered_slots=None, trust_pia=False, log=lambda *a: None):
        """party: list[Mon] (1..6). trade_slot: which of OUR slots to give away on the FIRST round
        (back-compat seed for offered_slots). anim_delay: frames to wait after START_TRADE before
        READY_FINISH (the local DoTradeAnim stand-in); defaults to DEFAULT_ANIM_FRAMES (1935) -
        tests pass a small value to finish quickly. mpid: GetMultiplayerId() seat side; MUST be 1
        (the Follower / RIGHT seat). decline: confirm-NO path - emit
        READY_CANCEL_TRADE immediately on the confirm prompt (graceful decline-to-leave).
        refuse_partner_deoxys_mew: treat an offered Deoxys/Mew as the PARTNER_MON_INVALID verdict
        (the host's illegitimate-legend gate; legitimacy is not offline-decodable so this is opt-in).
        trades: number of SEQUENTIAL trades to perform, 1..6. The wireless link
        STAYS UP after each trade and returns to the trade-select menu, re-running BufferTradeParties
        every entry (trade.c:935; trade_scene.c:2752 SetMainCallback2(gMain.savedCallback ==
        CB2_StartCreateTradeMenu)), so each round replays the FULL party-exchange -> select -> confirm
        -> anim -> commit dance. After the Nth trade the sim cancels-to-leave (REQUEST_CANCEL 0xEEAA,
        trade.c:2049). offered_slots: explicit list (len==trades) of OUR party indices to give away,
        one per round; MUST be distinct (the received mon lands in the offered slot after TradeMons -
        trade_scene.c:1054-1083 - so re-offering it would re-give a just-received mon). Defaults to
        [trade_slot, trade_slot+1, ...] filtered to distinct in-range slots (back-compat: trades==1 =>
        [trade_slot])."""
        # The sim sits at the RIGHT seat = the Follower = GetMultiplayerId()
        # == 1. Every OUT LINKCMD this engine emits is the GetMultiplayerId()==1 branch of
        # SetReadyToTrade (trade.c:1816) / the Follower paths; mpId 0 = Leader = LEFT seat, which
        # would emit the broadcasts we only ever react to. Lock it.
        assert mpid == 1, f"sim must be the RIGHT-seat Follower (mpId==1), got mpId={mpid}"
        self.party = list(party)
        self.trade_slot = trade_slot
        self.mpid = mpid
        # COSMETIC chair side - the RIGHT chair is Chair1 (VAR_0x8005=1, map x=7)
        # [data/scripts/cable_club.inc:644-649; data/maps/TradeCenter/map.json]. This feeds ONLY
        # gLocalLinkPlayer.id via SetLocalLinkPlayerId(gSpecialVar_0x8005) for local camera/sprite
        # placement [cable_club.c:840; link.c:338-341]; it does NOT drive any wire byte - every trade
        # gate uses GetMultiplayerId() (=mpId=1, fixed at RFU join), NOT the chair [trade_scene.c:
        # 727-731; trade.c:1816]. Recorded here so the sim models the RIGHT chair, but NO emitted byte
        # may depend on it (asserted by the test suite). Default 1 = the RIGHT chair.
        self.cosmetic_seat = 1
        self.lp = link_player or linkplayer.LinkPlayer()
        self.anim_delay = DEFAULT_ANIM_FRAMES if anim_delay is None else anim_delay
        self.decline = decline
        self.refuse_partner_deoxys_mew = refuse_partner_deoxys_mew
        # trust_pia: send block fragments fire-and-forget (once each) and let Pia's reliable layer
        # guarantee delivery, instead of the decomp's re-send-until-confirmed loop which floods our
        # high-RTT bridge. Default ON (the bridge needs it); --no-trust-pia restores the faithful
        # Switch behavior. Passed straight to each BlockSender. See block.py for the full rationale.
        self.trust_pia = trust_pia
        self.log = log
        self.info = getattr(log, "info", log)   # clean milestone sink (default-mode narration)

        # Multi-trade loop (1..6). offered_slots is the per-round distinct
        # original-slot list; trade_slot is the active per-round cursor.
        if not 1 <= trades <= 6:
            raise ValueError(f"trades must be 1..6, got {trades}")
        self.trades = trades
        self.offered_slots = resolve_offered_slots(offered_slots, trade_slot, trades,
                                                   party_size=len(self.party))
        if any(s >= len(self.party) for s in self.offered_slots):
            raise ValueError(f"offered_slots {self.offered_slots} exceed party size {len(self.party)}")
        self.round = 0                   # 0-based index of the current/next trade
        self.received_mons = []          # one received Mon per completed trade, in order
        self.leaving = False             # the configured trades are done; cancel-to-leave armed
        self.requested_cancel = False    # REQUEST_CANCEL has been queued for the graceful leave
        self.left_gracefully = False     # the host echoed *_CANCEL to our REQUEST_CANCEL
        self._offered = set()            # slots already given away (never re-offer)
        # the FIRST round's cursor is the first offered slot (preserves single-trade behavior).
        self.trade_slot = self.offered_slots[0]

        self.rx = block.BlockReceiver()
        self.sender = None
        # state_history records every state ENTERED in order (consecutive repeats collapsed), so the
        # transient S8_DONE at each commit is visible even when the next round re-arms to S1_LINK in
        # the same tick. Initialized before the first `self.state =` (the property setter appends).
        self.state_history = []
        self.state = S1_LINK

        # Standby / close-link barrier responder [link_rfu_2.c:1471-1602]. Created
        # once and persists across all N sequential trades; its host_count mirror
        # climbs monotonically as the same RFU link is reused. It answers the host's 0x6600/0x5F00
        # barriers (trade-menu entry, menu->scene seam, cancel-to-leave, and the 4-5 post-trade save
        # barriers) ONLY on VBlanks the engine would otherwise idle - never over a live block send or
        # a pending LINKCMD push (priority-1..4 below).
        self.barrier = barriermod.BarrierResponder(log=self.log)

        # Union-room -> trade-center ENTRY phase tracker (P0..P5). One-shot per
        # session; persists across all N trades but never re-fires (the post-trade
        # loop returns to CB2_StartCreateTradeMenu, not the seat barrier). The standby windows are
        # answered by self.barrier; the seat held-keys barrier by linkstate.py; here we only supply
        # the REQ-driven 100B trainer card and record the deterministic phase ordering.
        self.entry = EntryPhase(log=self.log)
        # the 100B trainer-card buffer the host pulls in Task_ExchangeCards [union_room.c:1758-1759].
        # Built from the LinkPlayer identity so OT/trainerId/version match the LinkPlayerBlock; wonder
        # card id 0 (CreateTrainerCardInBuffer setWonderCard=TRUE but the sim has no wonder card,
        # union_room.c:1865-1869). Cosmetic to the trade, but the host pulls it before the menu exists.
        self.trainer_card = linkplayer.build_trainer_card(self.lp, wonder_card_id=0)

        # send-staging phase trackers
        self._lp_sent = False
        self._party_sent = 0
        self._party600 = monmod.build_player_party(self.party)
        self._party_blocks = monmod.party_blocks(self._party600)

        # SEAT phase (black-screen cause). The real cable-club order is LinkPlayer(reqtype0) ->
        # STANDBY#1(0x6600 count0) -> card(reqtype2) -> STANDBY#2(count1) -> SEND_HELD_KEYS (the seat).
        # The host streams SEND_HELD_KEYS (0xBE00) ONLY once it has warped to the Trade Center and is at
        # its seat (gRfu.callback==SendKeysToRfu). So the host's FIRST 0xBE00 is the wire-observable "host
        # is at the seat" signal: we must NOT sit (emit READY 0x16) or run our own held-keys before it, or
        # we sit into an empty room (host still entering) and desync -> black screen. _host_in_seat latches
        # on that first host 0xBE00 and gates the sit + held-keys + the P4 trade-menu latch.
        self._host_in_seat = False
        self._host_ready = False          # host emitted READY (0x16) = its avatar seated -> we may sit
        self._player_ids_seen = False     # logged/validated the host's SEND_PLAYER_IDS once
        # received host data
        self.host_link_player = None
        self._host_party = bytearray(monmod.PARTY_MON_SIZE * PARTY_SIZE)
        self._host_party_blocks = 0
        self.host_cursor = None
        self.received_mon = None

        # trade-dance bookkeeping
        self._got_ribbons = False        # host streamed its giftRibbons = BufferTradeParties complete
        self._bt_settle = 0              # IN frames since the last host block/REQ (offline ribbons fallback)
        self._live = False               # set by the live sim: gate READY_TO_TRADE on full BufferTradeParties
        self._selected = False
        self._pending_push = None       # a LINKCMD block queued to send next
        self._anim_wait = None          # frames remaining before READY_FINISH [S7]
        self._finish_sent = False       # READY_FINISH has been emitted [S7 early-arrival guard]
        self._pending_confirm = False   # CONFIRM_FINISH arrived before READY_FINISH; defer commit
        self._confirmed = False         # confirm prompt processed (INIT_BLOCK / cancel decided) [S6]
        self._cancel_wait = None        # frames remaining before a 180-frame READY_CANCEL [S6]
        self._cancel_after_send = False # a cancel block is streaming; leave once it completes
        self.commits = 0                # number of trades committed (== len(received_mons) when valid)
        self._finish_sent_at_last_commit = False  # S7 invariant observable (READY_FINISH<commit)
        self.done = False
        self.cancelled = False

        # CHILD-INITIATED standby barriers [link_rfu_2.c:1566-1573]. The child reaches the SAME
        # trade.c / trade_scene.c state the host does and calls SetLinkStandbyCallback() ITSELF, so the
        # engine INITIATEs a barrier at each FSM standby point (a)..(d) so a strict-ROM host parked in
        # the leader branch (which WAITS for the child) is unblocked. (a)/(b) are SOFT initiates (the
        # selection / anim is not stalled, so a non-participating host does not race a frozen joiner);
        # (c) the save chain and (d) the cancel-exit are QUIESCENT (emit only the 0x6600).
        self._barrier_initiated_menu = False  # (a) trade-menu-entry standby initiated this round
        self._barrier_initiated_seam = False  # (b) menu->scene-seam standby initiated this round
        # WARP-QUIESCE standbys (fixes the host hanging at trade-room entry on a black screen). The
        # reference capture's guest emits READY_EXIT_STANDBY count=0 right AFTER the LinkPlayer exchange
        # and count=1 AFTER the trainer card - the host GATES the card pull / the seat on seeing them
        # (mutual barriers). These are not reactive; they are CHILD-INITIATED. Session one-shots
        # (NOT reset per round - the post-trade loop re-enters the menu, not the warp).
        self._barrier_initiated_warp1 = False  # post-LinkPlayer warp-quiesce (count 0)
        self._barrier_initiated_warp2 = False  # post-card warp-quiesce (count 1)
        self._warp1_emits = 0           # NEW count-0 standby frames emitted (BOUNDED burst, not a flood)
        self._warp2_emits = 0           # NEW count-1 standby frames emitted
        self._warp3_emits = 0           # NEW count-2 standby frames (post-seat, warp into trade scene)
        self._warp4_emits = 0           # NEW count-3 standby frames (post-seat)
        self._barrier_initiated_warp3 = False
        self._barrier_initiated_warp4 = False
        self._warp3_regap = 0            # idle frames since the count=2 burst, before re-arming it (sustain)
        self._warp4_regap = 0            # idle frames since the count=3 burst, before re-arming it (sustain)
        self._self_seated = False        # we have emitted our READY (0x16) at the cable seat
        self._post_seat_wait = 0         # held-keys keepalive ticks left before the post-seat standbys
        self._save_barriers = False     # (c) post-trade save barrier chain is running [trade_scene 2566+]
        self._save_settle = 0           # consecutive host-idle frames since the last save barrier
        self._save_started = False      # the FIRST save-chain round has been initiated (gate the inter-round pace)
        self._save_round_wait = 0       # frames waited since the last save round completed (inter-round pace)
        self._cancel_barrier_active = False  # (d) cancel-exit standby running, finish when it passes
        self._return_field_barrier_active = False  # (e) return-to-field sync standby (count+1 after (d))
        # POST-CANCEL OVERWORLD: after the cancel-exit standby passes, the real game
        # does NOT disconnect - CB_ExitCanceledTrade returns to the OVERWORLD (CB2_ReturnToFieldFrom-
        # Multiplayer), the held-keys engine RE-ARMS (StartSendingKeysToLink), the player walks to the
        # door (EXIT_ROOM 0x17), and only THEN the host-initiated READY_CLOSE_LINK (0x5F00) round runs
        # before TryDisconnectRfu. This flag re-arms in_seat_phase (held-keys keepalive) and keeps the
        # barrier responder LIVE so we answer the host's CLOSE instead of vanishing ~23s early.
        self._post_cancel_overworld = False
        # The host has walked out of the trade room and broadcast LINK_KEY_CODE_EXIT_ROOM (0x17): it is now
        # at KeyInterCB_WaitForPlayersToExit ("You will be escorted out of the room. Please wait.") BLOCKING
        # until ALL players are EXITING_ROOM [overworld.c:2962-2981]. The orchestrator responds by emitting
        # OUR EXIT_ROOM (linkstate.exit()) so the host marks us EXITING_ROOM -> DoLinkRoomExit -> CLOSE.
        self._host_exiting = False

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value
        if not self.state_history or self.state_history[-1] != value:
            self.state_history.append(value)

    @property
    def in_seat_phase(self):
        """True while the sim is in the OVERWORLD/SEAT phase - the ONLY phase the real child runs the
        held-keys engine (0xBE00 SEND_HELD_KEYS). This is the explicit signal sim.py gates the
        held-keys takeover on: outside it, an idle VBlank is an ALL-ZERO idle slot, NOT a 0xBE00.

        DECOMP - the held-keys CUTOFF is the cable-seat exit (entry P3), NOT the first mon selection:
        SendKeysToRfu (the 0xBE00 emitter) only runs while gRfu.callback == SendKeysToRfu, armed by
        StartSendingKeysToLink at the cable-seat / link-reestablish [cable_club.c:615; link.c:721-727;
        link_rfu_2.c:1092-1101]. gRfu.callback is a SINGLE shared RFU-job slot; the moment we warp out
        of the cable seat, Task_StartWirelessTrade case 0 calls ClearLinkRfuCallback() -> gRfu.callback
        = NULL [cable_club.c:918] and case 2 installs Rfu_LinkStandby [cable_club.c:932] - so held keys
        are OFF before CB2_CreateTradeMenu even runs. The trade menu's party exchange (BufferTradeParties
        at CB2_CreateTradeMenu case 6 [trade.c:935]) and the later gMain.callback1 = CB1_UpdateLink swap
        (case 22 [trade.c:1085]) are BOTH after that point, so from the party exchange (S4) through the
        trade FSM and the post-trade save the child emits all-zero idle, NOT held keys. SendKeysToRfu is
        only re-armed when returning to the OVERWORLD field (FieldCB_ReturnToFieldWirelessLink ->
        StartSendingKeysToLink [field_fadetransition.c:226]), after the trade. The seat phase is
        therefore exactly P0..P3 (union-room entry + cable seat), so we gate on entry.seat_phase_over,
        which latches at P4 (the trade menu opens / the FIRST party block is on the wire) - strictly
        EARLIER than entry.complete (P5, the first selection). The latch never clears (the post-trade
        loop re-enters CB2_StartCreateTradeMenu, not the cable seat, trade_scene.c:2752; the keys
        callback is only re-armed back in the overworld), so subsequent trades stay all-zero too.

        EXCEPTION: after the cancel-exit standby, _post_cancel_overworld re-arms held-keys - the real
        game returns to the OVERWORLD field there and StartSendingKeysToLink fires again,
        so the leave tail emits 0xBE00 keepalive (+ EXIT_ROOM 0x17) rather than going dead."""
        return self._post_cancel_overworld or not self.entry.seat_phase_over

    @property
    def established(self):
        """gReceivedRemoteLinkPlayers equivalent [link_rfu_2.c:1879]: the LinkPlayerBlock has been
        exchanged BOTH ways (our 200B LinkPlayer streamed out AND the host's LinkPlayer received).
        SendKeysToRfu (the 0xBE00 held-keys emitter) is gated on this [link_rfu_2.c:1069] - the C2 fix:
        held keys + sit()/READY must NOT fire BEFORE this latches, or our tagged 0xBE00 races ahead of
        the NI/block handshake and the host faults the childSendCmdId check in <=5 frames. Pre-link
        VBlanks (before this is True) must be bare all-zero IDLE slots (tag untouched). Monotone:
        once both LinkPlayers are exchanged it never clears on the trade path (the post-trade loop
        re-enters the menu, not the union-room entry)."""
        return self._lp_sent and self.host_link_player is not None

    @property
    def host_in_seat(self):
        """The host has reached its cable-club seat (started streaming SEND_HELD_KEYS 0xBE00), AFTER the
        LinkPlayer + standby#1 + card + standby#2 sequence. This is the wire-observable gate for OUR sit
        (READY 0x16) and held-keys engine: sitting before this races a seat-down into an empty room while
        the host is still warping/walking -> desync/black screen (seat-barrier). Monotone latch."""
        return self._host_in_seat

    @property
    def host_ready(self):
        """The host emitted READY (LINK_KEY_CODE_READY 0x16) = its own avatar reached the chair and sat
        (reference capture: the host stands/walks first, then READY). The gate for OUR sit: sitting before this (an
        early READY at room-load while the host is in 'Please wait'/walking) faults the host's cable-seat
        FSM immediately (observed as a comms error on trade-room load). We emit EMPTY keepalive until then."""
        return self._host_ready

    @property
    def host_exiting(self):
        """The host walked out of the trade room and broadcast LINK_KEY_CODE_EXIT_ROOM (0x17): it is at
        KeyInterCB_WaitForPlayersToExit ("You will be escorted out of the room. Please wait.") and BLOCKS
        until ALL players are EXITING_ROOM [overworld.c:2962-2981]. The orchestrator must respond with OUR
        EXIT_ROOM (lstate.exit()) so the host sees us EXITING_ROOM -> DoLinkRoomExit -> READY_CLOSE_LINK."""
        return self._host_exiting

    def note_self_seated(self):
        """The orchestrator emitted OUR READY (0x16) at the cable seat (lstate.sit()). Arms the POST-SEAT
        warp-into-scene standbys (count=2 then count=3) (reference capture: after BOTH sit, the guest drives
        those two rounds before the host pulls the party). A short POST_SEAT_STANDBY_DELAY of held-keys keepalive runs
        first so our READY actually goes out on the wire before tick() switches the slot to the standby."""
        if self._self_seated:
            return
        self._self_seated = True
        self._post_seat_wait = POST_SEAT_STANDBY_DELAY

    # ---- receive ------------------------------------------------------------
    def feed_in_frame(self, unwrapped):
        """Feed one decoded IN gba 0x54 frame (gbaframe.parse_in)."""
        completed, reqs = self.rx.feed_frame(unwrapped)
        # SEAT signal: latch _host_in_seat the first time the host streams a SEND_HELD_KEYS (0xBE00) slot
        # - it has reached its Trade-Center seat (gRfu.callback==SendKeysToRfu). Everything before this
        # (LinkPlayer/standby/card) must NOT see us sit. (black-screen / seat-barrier)
        if unwrapped is not None and not self._host_ready:
            for _mpid, slot in unwrapped.get("positional", []):
                r = rfu.parse_slot(slot)
                if not r:
                    continue
                op = r["word0"] & 0xFF00
                # SEND_PLAYER_IDS (0x7700): host broadcasts playerCount (word1) + ids[] (word2..) right
                # after the NI handshake. Validate our hardcoded RIGHT-seat mpId against ids[0] so a
                # host that seats us elsewhere is a LOUD warning, not a silent mis-addressed trade.
                if op == rfu.SEND_PLAYER_IDS and not self._player_ids_seen:
                    self._player_ids_seen = True
                    count = int.from_bytes(slot[2:4], "little")
                    id0 = int.from_bytes(slot[4:6], "little")
                    self.log(f"entry: host SEND_PLAYER_IDS playerCount={count} ids[0]={id0} (our mpId={self.mpid})")
                    if count != 2 or id0 != self.mpid:
                        self.log(f"entry: WARNING SEND_PLAYER_IDS (count={count}, ids[0]={id0}) does not "
                                 f"match the 2-player RIGHT-seat assumption (mpId {self.mpid}) - trade may mis-address")
                if op == rfu.SEND_HELD_KEYS:
                    if not self._host_in_seat:
                        # FIRST host held-keys = host entered the Trade-Center field (gRfu.callback==
                        # SendKeysToRfu). Start OUR held-keys keepalive (EMPTY) - but do NOT sit yet.
                        self._host_in_seat = True
                        self.entry.on_seat_reached()
                        # warp-quiesce behind us; clear any leftover reactive 0x6600 from the host's echoes.
                        self.barrier.reset_to_idle()
                        self.log("entry: host entered the trade room (first SEND_HELD_KEYS) -> emit EMPTY keepalive")
                        self.info("Host entered the trade room.")
                    # The host emits READY (LINK_KEY_CODE_READY 0x16) only once ITS avatar reaches the
                    # chair and sits (reference capture: ~17 EMPTY then walk then READY). We must NOT sit before that
                    # - an early READY at room-load (avatar at spawn, host in "Please wait") faults the
                    # host's seat FSM immediately (observed as a comms error on load). Latch host_ready off the
                    # host's READY so the orchestrator sits WITH the host (both -> PLAYER_LINK_STATE_READY
                    # -> GetCableClubPartnersReady SUCCESS).
                    if (int.from_bytes(slot[2:4], "little") & 0xFF) == 0x16 and not self._host_ready:
                        self._host_ready = True
                        self.log("entry: host emitted READY (0x16) - host is seated; we may sit now")
                        self.info("Host sat down.")
                        break
        # POST-CANCEL EXIT: once back in the overworld, the host walks to the south exit, confirms leaving,
        # and broadcasts LINK_KEY_CODE_EXIT_ROOM (0x17) in its held-keys (KeyInterCB_SendExitRoomKey), then
        # BLOCKS at KeyInterCB_WaitForPlayersToExit ("You will be escorted out of the room. Please wait.")
        # until ALL players are EXITING_ROOM [overworld.c:2962-2981; cable_club.inc TradeCenter_TerminateLink
        # -> ExitLinkRoom]. The host marks US EXITING_ROOM only when WE send our OWN EXIT_ROOM (Handle-
        # LinkPlayerKeyInput case 2751). The seat-phase scan above is gated off (_host_ready), so detect the
        # host's EXIT_ROOM HERE; the orchestrator then has linkstate emit ours -> AreAllPlayersInLinkState(
        # EXITING_ROOM) -> CableClub_EventScript_DoLinkRoomExit -> READY_CLOSE_LINK (c=13). (Reference
        # captures: host EXIT_ROOM IN first, joiner EXIT_ROOM OUT ~3.7s later, THEN the host-led CLOSE.)
        if self._post_cancel_overworld and not self._host_exiting and unwrapped is not None:
            for _mpid, slot in unwrapped.get("positional", []):
                r = rfu.parse_slot(slot)
                if (r and (r["word0"] & 0xFF00) == rfu.SEND_HELD_KEYS
                        and (int.from_bytes(slot[2:4], "little") & 0xFF) == 0x17):
                    self._host_exiting = True
                    self.log("post-cancel: host emitted EXIT_ROOM (0x17) - it is walking out and waiting "
                             "for ALL players to exit; respond with our EXIT_ROOM [overworld.c:2962-2981]")
                    self.info("Host is leaving the room...")
                    break
        # Surface the host's barrier op to the standby responder. The host broadcasts 0x6600/0x5F00 in
        # a positional slot (canonically mpId 0, but possibly coalesced at a later offset - scanned by
        # OP in _host_barrier_in_frame). on_in_slot drives BOTH the completion of a CHILD-INITIATED
        # barrier (the host echoed our count -> readyExitStandby latches, the round passes
        # [link_rfu_2.c:1178-1180,1541-1547]) AND the reactive path (the host initiated; we mirror it).
        # observe_frame drives the per-frame watchdogs every IN frame so an unanswered initiated barrier
        # (non-participating host) releases the FSM and a finished reactive round resumes trade traffic.
        host_slot = self._host_barrier_in_frame(unwrapped)
        saw_barrier = host_slot is not None
        if saw_barrier:
            self.barrier.on_in_slot(host_slot)
        if unwrapped is not None:
            self.barrier.observe_frame(saw_barrier)
            # Save-chain settle tracker: consecutive IN frames with NO host barrier op. The post-trade
            # save chain (_run_save_chain) ends when the host stops participating (it has finished its
            # 4-5 standby rounds and moved on / returned to the menu) - detected by this counter.
            if self._save_barriers:
                self._save_settle = 0 if saw_barrier else self._save_settle + 1
        # If we are in the post-trade save chain but the host begins re-exchanging (it pulls a block, or
        # streams one of its OWN, mpId 0) instead of doing save barriers, this host does not model the
        # save chain (the happy-path MockHost): end the chain immediately so the engine processes the
        # exchange. NB only a HOST block (mpId 0) or a REQ counts - the mpId-1 entries in `completed`
        # are reflections of OUR OWN just-sent block (e.g. READY_FINISH), which must NOT end the chain.
        host_reexchange = bool(reqs) or any(mpid == 0 for mpid, _c, _d in completed)
        if self._save_barriers and host_reexchange:
            self._save_barriers = False
            # Drop any in-flight save standby (e.g. a freshly-initiated count=N round the host will never
            # answer - it has left the chain for the menu) to IDLE, preserving local_count. Else priority-5
            # keeps emitting that stale count on idle VBlanks through Phase M until the IDLE watchdog trips
            # (~120f of stale 0x6600 the re-exchanging host's recv gate ignores). Same cleanup as the
            # warp-quiesce hand-off at the seat (line ~588).
            self.barrier.reset_to_idle()
            self.log("save-chain: host re-exchanging (REQ/block) -> ending chain, resume trade")
        for reqtype in reqs:
            self._on_req(reqtype)
        host_block = any(mpid == 0 for mpid, _c, _d in completed)
        for mpid, count, data in completed:
            if mpid == 0:               # host's own blocks (mpId 0)
                self._on_host_block(count, data)
            # mpId 1 = the reflection of our own block = the wire ACK; consumed by the sender
        # BufferTradeParties settle [READY_TO_TRADE gate, offline ribbons fallback]: count IN frames
        # since the host last pulled a block (REQ) or streamed one (mpId 0). The offline MockHost sends
        # no ribbons, so once it goes quiet past BUFFERTRADE_SETTLE we treat the exchange as done.
        if unwrapped is not None:
            self._bt_settle = 0 if (reqs or host_block) else self._bt_settle + 1

    def _host_barrier_in_frame(self, unwrapped):
        """Return the parsed host barrier slot for THIS frame, or None. Reads the raw positional slots
        so it reflects exactly what the host sent this VBlank - a stale/sticky previous op never leaks
        in (the watchdogs depend on per-frame truth).

        A standby/close slot carries NO owner field (parse_slot only reads count for these ops), so we
        cannot key it by mpId - and a host 0x6600 COALESCED into a later positional slot (offset 26+,
        not the canonical mpId-0 offset 12) would be missed by an mpId==0-only scan, deadlocking the
        barrier. Dispatch purely by OP, scanning ALL positional slots: the first slot carrying a
        barrier op (any position) is the host's barrier broadcast. We skip OUR OWN reflected barrier
        (the mpId-1 echo of a slot we emitted) so we never complete a round off our own reply."""
        if not unwrapped:
            return None
        for mpid, slot in unwrapped.get("positional", []):
            if mpid == self.mpid:
                continue                 # our own reflected slot, not the host's broadcast
            d = rfu.parse_slot(slot)
            if d is not None and d["op"] in (rfu.READY_EXIT_STANDBY, rfu.READY_CLOSE_LINK):
                return d
        return None

    def _begin_send(self, buf):
        """Start a block send. Reset the peer-1 reflection first: until the host reflects THIS
        block's INIT (one round later), peer-1 still holds the PREVIOUS block's completed state,
        which would falsely satisfy the send gates and complete the new block after one fragment.
        Clearing it makes the sender wait for the fresh wire ACK (true against the real host too)."""
        self.rx.peers[1] = block.RecvBlock()
        self.sender = block.BlockSender(buf, trust_pia=self.trust_pia)
        return self.sender

    def _on_req(self, reqtype):
        """Host pulled a block: start sending the staged buffer at the host-requested size. Keyed on
        the REQTYPE selector (not just the size) so BLOCK_REQ_SIZE_100 unambiguously means the ENTRY
        trainer card [link.c:185-190; link_rfu_2.c:1172-1173]. The 100B card pull is the union-room ->
        trade-center entry handshake (Task_ExchangeCards [union_room.c:1758-1759]); it is REQ-driven so
        it is robust whether or not the live host actually issues it (live residual)."""
        if self.sender is not None and not self.sender.done:
            # already streaming a block. A REQ here is the host RE-PULLING the SAME block until it
            # lands (RFU re-issues the pull every frame, link_rfu_2.c:1296) - NOT a new pull; serving
            # it would re-send the next party pair early (drops/duplicates a pair). The host's
            # pull for the NEXT block only arrives AFTER it has our current one + a processing gap, by
            # which time the sender is DONE (poll_send_done finishes it even while the window is gated).
            return
        size = REQ_SIZE.get(reqtype, 200)
        buf = self._block_for_size(reqtype, size)
        self.log(f"REQ type={reqtype} size={size} -> send {len(buf)}B")
        self._begin_send(buf)

    def _block_for_size(self, reqtype, size):
        if reqtype == BLOCK_REQ_SIZE_100:
            # ENTRY trainer-card pull (Task_ExchangeCards). Supply the structured 100B card and record
            # the entry phase (the host pulled us before any trade menu existed). count = 9.
            self.entry.on_card_req()
            self.entry.on_card_supplied()
            return self.trainer_card
        if size == 200:
            # A size-200 pull is the trade menu's BufferTradeParties exchange (LinkPlayer one-shot, then
            # the 3 party pairs [trade.c:1444-1542]). It runs only AFTER Task_StartWirelessTrade cleared
            # the keys callback [cable_club.c:918], so emitting/answering it means we have warped out of
            # the cable seat: latch the held-keys CUTOFF (P4 trade menu) here, well before the first mon
            # selection (P5). Idempotent / monotonic - safe to call on every party pair and every round.
            # GATED on _host_in_seat: a size-200 pull BEFORE the host reaches its seat is the LinkPlayer
            # one-shot (reqtype 0, Task_PlayerExchange), NOT BufferTradeParties - it must NOT latch the
            # held-keys cutoff or we'd never run the seat held-keys (black-screen).
            if self._host_in_seat:
                self.entry.on_trade_menu_open()
            # DECOMP-FAITHFUL LinkPlayer one-shot: the LinkPlayerBlock is exchanged EXACTLY ONCE,
            # during the union-room -> cable-club entry (Task_PlayerExchange [link_rfu_2.c:1813-1900]
            # case 3: SendBlockRequest(BLOCK_REQ_SIZE_NONE) -> sBlockRequests[NONE] =
            # gLocalLinkPlayerBlock, 200B [link_rfu_2.c:232]). gReceivedRemoteLinkPlayers latches
            # TRUE there [1879] and is NEVER re-cleared on the trade path, so the per-menu
            # BufferTradeParties [trade.c:1444-1542] NEVER re-pulls a LinkPlayer - it answers each
            # BLOCK_REQ_SIZE_200 with a PARTY pair (gPlayerParty[0..1]/[2..3]/[4..5]). The compressed
            # model rolls the entry exchange into ROUND 0's first size-200 pull; ROUNDS >= 1 are
            # PARTY-FIRST. _lp_sent is a session one-shot that _reset_round_state does NOT clear, so
            # rounds 2..6 (and the cancel-to-leave round) never resend the LinkPlayer as party
            # block #1 - which would shift the party by one and DROP party pair #3 (gPlayerParty[4..5]).
            if self.round == 0 and not self._lp_sent:
                self._lp_sent = True
                return linkplayer.build_block(self.lp).ljust(200, b"\x00")
            i = self._party_sent
            self._party_sent += 1
            return self._party_blocks[i] if i < len(self._party_blocks) else b"\x00" * 200
        if size == 100:
            return self.trainer_card    # any other 100B pull = the trainer card too
        if size == 220:
            return b"\x00" * 220        # mail (none)
        if size == 40:
            return b"\x00" * 40         # giftRibbons (none)
        return b"\x00" * size

    def _on_host_block(self, count, data):
        if count == COUNT_TRAINER_CARD and not self.entry.complete:
            # ENTRY: the host's 100B trainer card (Task_ExchangeCards). Reassemble it into the entry's
            # recvBuffer[0]-equivalent and CONSUME it WITHOUT advancing the trade FSM - it is cosmetic
            # (CopyTrainerCardData populates the card-view UI only [union_room.c:1769-1779]). Only
            # treated as a card BEFORE the trade menu is live, so a same-count block later in the trade
            # (none exist on this path) could never be mistaken for it.
            self.entry.on_host_card(data)
            return
        if count == COUNT_LINKCMD:
            cmd = int.from_bytes(data[0:2], "little")
            cursor = int.from_bytes(data[2:4], "little")
            self._on_linkcmd(cmd, cursor)
        elif count == COUNT_PARTY:
            # A host party/LinkPlayer block (count=17, len=204; ceil(200/12)) is the trade menu's
            # BufferTradeParties exchange,
            # which the host streams only AFTER both sides warped out of the cable seat (the keys
            # callback was already cleared at Task_StartWirelessTrade [cable_club.c:918]). Latch the
            # held-keys CUTOFF (P4) on receiving it too - covers a host that streams its party first.
            # GATED on _host_in_seat: the host's pre-seat count-17 block is its LinkPlayer (S1), not the
            # party exchange, so it must not latch the cutoff before the seat (black-screen).
            if self._host_in_seat:
                self.entry.on_trade_menu_open()
            lp, ok = linkplayer.parse_block(data)
            # The LinkPlayer block is identified by its GameFreak magic (parse_block ok), NOT by
            # "host_link_player is None" - in round 2+ the host RE-STREAMS its LinkPlayer first
            # (BufferTradeParties re-runs every menu entry, trade.c:935), so a valid-magic block is
            # always the LinkPlayer and must never be mistaken for party block #1.
            if ok:
                if self.host_link_player is None:
                    self.host_link_player = lp
                    self.log(f"host LinkPlayer: {lp.name} v0x{lp.version:04x}")
                    self.info("Exchanged player info with the host.")
            elif self._host_party_blocks < 3:
                i = self._host_party_blocks
                self._host_party[i * 200:(i + 1) * 200] = data[:200]
                self._host_party_blocks += 1
                self.log(f"host party block #{i + 1}/3")
                if self._host_party_blocks == 3 and self.state == S1_LINK:
                    self.state = S4_PARTY
        elif count in (COUNT_MAIL, COUNT_RIBBON):
            # Host mail (count=19, 220B) / giftRibbons (count=4, 40B): cosmetic for the trade decision
            # (which uses only the party + LinkPlayer), but the host DOES stream them in BufferTradeParties
            # - consume + log so they are not silently dropped and a mail-bearing trade can be modeled
            # later.
            self.log(f"host {'mail' if count == COUNT_MAIL else 'giftRibbons'} block "
                     f"(count={count}) - consumed (cosmetic, not trade-affecting)")
            if count == COUNT_RIBBON:
                # giftRibbons is the LAST block of BufferTradeParties (party x3 -> mail -> ribbons,
                # trade.c:1444-1542). Receiving it = the full party exchange is done; only now may we
                # send READY_TO_TRADE (we were sending it after just the 3 party blocks, i.e.
                # DURING BufferTradeParties (before the host pulled mail/ribbons), so the host - not yet
                # in the trade menu - never advanced to SET_MONS -> stuck at "Communication standby").
                self._got_ribbons = True

    def _on_linkcmd(self, cmd, cursor):
        self.log(f"<- LINKCMD {LINKCMD_NAMES.get(cmd, hex(cmd))} cursor={cursor}")
        if cmd == SET_MONS_TO_TRADE:
            # [S6] SET_MONS_TO_TRADE -> partnerCursorPosition = recv[0][1] + PARTY_SIZE; the host
            # then shows the confirm prompt (CB_PRINT_IS_THIS_OKAY, trade.c:1653-1657). We store the
            # RAW cursor (the received-mon index into the host party is cursor % PARTY_SIZE, used by
            # _commit) and enter S6_CONFIRM, but DO NOT immediately queue INIT_BLOCK - the decomp
            # gates it behind the confirm prompt + CheckValidityOfTradeMons (see _run_confirm).
            self.host_cursor = cursor
            if self.state in (S5_SELECT, S4_PARTY):
                self.state = S6_CONFIRM
                self._run_confirm()
        elif cmd == START_TRADE:
            # Once we've decided to cancel (READY_CANCEL/REQUEST_CANCEL queued), a real Leader would
            # have latched partnerConfirmStatus=STATUS_CANCEL and never START (trade.c:1629-1631 ->
            # Leader_HandleCommunication). Ignore a late START so the cancel-to-leave wins.
            if self.cancelled:
                return
            # [S7] START_TRADE -> CB_WAIT_TO_START_TRADE -> the wireless DoTradeAnim runs for
            # anim_delay frames before READY_FINISH (trade.c:1659-1661 -> trade_scene.c:2527-2536).
            self.state = S7_ANIM
            self._anim_wait = self.anim_delay
        elif cmd == CONFIRM_FINISH_TRADE:
            if self.cancelled:
                return                  # leaving: ignore a late CONFIRM
            # [S7 early-arrival guard] CONFIRM_FINISH is Leader-only and only sent once BOTH finish
            # statuses are READY (CB2_WaitTradeComplete, trade_scene.c:2547-2559). The host buffers
            # (latches) our READY_FINISH the frame it lands, so with a short anim_delay CONFIRM can
            # arrive before our own countdown elapses. The joiner already swapped locally in
            # CB2_UpdateLinkTrade (2533) BEFORE sending READY_FINISH, then WAITS for CONFIRM; to keep
            # the FSM order (READY_FINISH -> commit) deterministic, defer the commit until
            # READY_FINISH has been emitted.
            if self._finish_sent:
                self._commit()
            else:
                self._pending_confirm = True
                self.log("CONFIRM_FINISH early-arrival: deferring commit until READY_FINISH sent")
        elif cmd in (BOTH_CANCEL_TRADE, PLAYER_CANCEL_TRADE, PARTNER_CANCEL_TRADE):
            # The leader echoed a *_CANCEL (trade.c:1637-1666). Distinguish OUR graceful cancel-to-
            # leave (we requested it: requested_cancel) from an unexpected host-initiated cancel.
            self.state = S_CANCEL
            self.cancelled = True
            if self.requested_cancel:
                self.left_gracefully = True
                self.log(f"<- {LINKCMD_NAMES.get(cmd, hex(cmd))}: graceful cancel acknowledged")
                self.info("Trade cancelled (mutual).")
            else:
                self.log(f"<- {LINKCMD_NAMES.get(cmd, hex(cmd))}: host cancelled the trade")
            # [barrier (d)] cancel-exit standby. ONLY LINKCMD_BOTH_CANCEL_TRADE routes through
            # CB_INIT_EXIT_CANCELED_TRADE -> SetLinkStandbyCallback() [trade.c:1643-1646,2117-2132];
            # PLAYER/PARTNER_CANCEL go to CB_HandleTradeCanceled (back to the menu, no standby). So a
            # BOTH_CANCEL arms a CHILD-INITIATED standby barrier before the final exit (the host's
            # leader branch WAITS for us here too - the deadlock fix); we set `done` only once it
            # passes (host echo, or the offline watchdog against a non-participating host). The other
            # cancels finish immediately.
            if cmd == BOTH_CANCEL_TRADE:
                self._cancel_barrier_active = True
                self.barrier.initiate(barriermod.STANDBY)
                self.log("barrier (d): INITIATE cancel-exit standby [trade.c:2117-2132]")
            else:
                self.done = True

    # ---- validity gates (S5 select / S6 confirm) ----------------------------
    def _num_other_alive(self, slot):
        """Count OUR party mons (excluding `slot`) that are non-empty - the numMonsLeft loop in
        CanTradeSelectedMon (trade.c:2809-2813) / CheckValidityOfTradeMons hasLiveMon
        (trade.c:1958-1962). Eggs are excluded there too; we cannot decode the egg flag offline so
        non-empty (species present) is the stand-in (live residual)."""
        n = 0
        for i, m in enumerate(self.party):
            if i == slot:
                continue
            if not m.is_empty:
                n += 1
        return n

    def _is_valid_slot(self, slot):
        """Stand-in for CanTradeSelectedMon == CAN_TRADE_MON (trade.c:2745-2818): the slot is in
        range, points at a non-empty mon, and trading it would NOT leave us with no other mon
        (CANT_TRADE_LAST_MON guard). Returns True iff READY_TO_TRADE may be emitted [S5]."""
        if not (0 <= slot < len(self.party)):
            return False
        if self.party[slot].is_empty:
            return False
        return self._num_other_alive(slot) > 0

    def _trade_menu_live(self):
        """The trade menu/link is 'live' once the party EXCHANGE has fully finished - mirroring that
        the menu opens AFTER BufferTradeParties (trade.c:1444-1542), not interleaved with the dance.
        Live = our LinkPlayer + all party blocks have been staged out AND the host party is fully
        received [S5]."""
        # ...AND the FULL BufferTradeParties has finished (the host streamed its giftRibbons - the last
        # block - or, offline where the MockHost sends no ribbons, the host has gone quiet past the
        # settle). Sending READY_TO_TRADE DURING BufferTradeParties (after only the 3 party blocks, while
        # the host is still pulling mail/ribbons and not yet in the trade menu) left the host stuck at
        # "Communication standby" - it never advanced to SET_MONS.
        base = (self._host_party_blocks >= 3 and self._lp_sent
                and self._party_sent >= len(self._party_blocks))
        if not self._live:
            return base                  # offline MockHost sends SET_MONS right after the party (no
            #                              mail/ribbons), and its tests expect READY_TO_TRADE then.
        return base and (self._got_ribbons or self._bt_settle >= BUFFERTRADE_SETTLE)

    def _partner_mon_invalid(self):
        """Stand-in for the PARTNER_MON_INVALID branch of CheckValidityOfTradeMons (trade.c:1965-
        1968): the host's offered mon (host party slot host_cursor % PARTY_SIZE) is an illegitimate
        Deoxys/Mew. Legitimacy (MON_DATA_MODERN_FATEFUL_ENCOUNTER) is not offline-decodable, so this
        only fires when refuse_partner_deoxys_mew is set and the offered species is Deoxys/Mew."""
        if not self.refuse_partner_deoxys_mew or self.host_cursor is None:
            return False
        idx = self.host_cursor % PARTY_SIZE
        off = idx * monmod.PARTY_MON_SIZE
        offered = monmod.Mon(bytes(self._host_party[off:off + monmod.PARTY_MON_SIZE]))
        return offered.species in (SPECIES_MEW, SPECIES_DEOXYS)

    def _confirm_verdict(self):
        """CheckValidityOfTradeMons stand-in (trade.c:1951-1973). PARTNER_MON_INVALID takes priority
        (checked first in the decomp, line 1965), then PLAYER_MON_INVALID (last-alive), else
        BOTH_MONS_VALID. Returns one of PLAYER_MON_INVALID / BOTH_MONS_VALID / PARTNER_MON_INVALID."""
        if self._partner_mon_invalid():
            return PARTNER_MON_INVALID
        if self._num_other_alive(self.trade_slot) == 0:
            return PLAYER_MON_INVALID
        return BOTH_MONS_VALID

    def _run_confirm(self):
        """[S6] The confirm prompt (CB_PRINT_IS_THIS_OKAY -> CB_PROCESS_CONFIRM_TRADE_INPUT,
        trade.c:2073-2029). Routes on the YES/NO config + CheckValidityOfTradeMons:
          decline=True  -> confirm-NO: IMMEDIATE READY_CANCEL_TRADE (trade.c:2019-2023).
          BOTH_MONS_VALID -> confirm-YES: INIT_BLOCK, IMMEDIATE on IsLinkTaskFinished (1991-1996).
          PLAYER_MON_INVALID -> READY_CANCEL_TRADE after a 180-frame QueueAction (1986-1990).
          PARTNER_MON_INVALID -> READY_CANCEL_TRADE after a 180-frame QueueAction (1997-2001).
        All cancel paths set self.cancelled and print the leave intent."""
        if self._confirmed:
            return
        self._confirmed = True
        if self.decline:
            self.log("confirm: NO (declining) -> READY_CANCEL_TRADE (immediate) [trade.c:2019-2023]")
            self.info("Declining the trade; cancelling to leave.")
            self._pending_push = linkcmd_block(READY_CANCEL_TRADE)
            self.cancelled = True
            return
        verdict = self._confirm_verdict()
        if verdict == BOTH_MONS_VALID:
            self.log("confirm: BOTH_MONS_VALID -> INIT_BLOCK (immediate) [trade.c:1991-1996]")
            self._pending_push = linkcmd_block(INIT_BLOCK)          # confirm-YES (immediate)
        elif verdict == PLAYER_MON_INVALID:
            self.log("confirm: PLAYER_MON_INVALID -> READY_CANCEL_TRADE in 180f [trade.c:1986-1990]")
            self.info("Cannot keep our last living Pokémon; cancelling to leave.")
            self._cancel_wait = INVALID_CANCEL_DELAY
            self.cancelled = True
        else:  # PARTNER_MON_INVALID
            self.log("confirm: PARTNER_MON_INVALID -> READY_CANCEL_TRADE in 180f [trade.c:1997-2001]")
            self.info("Host offered an illegitimate Pokémon; cancelling to leave.")
            self._cancel_wait = INVALID_CANCEL_DELAY
            self.cancelled = True

    def _commit(self):
        """CONFIRM_FINISH received (and READY_FINISH already emitted): trade `self.round` is
        committed; capture the received mon and apply the LOCAL party swap (mirror TradeMons,
        trade_scene.c:1054-1083: SWAP(gPlayerParty[offeredSlot], gEnemyParty[partnerIdx]) - the
        received mon now occupies our offered slot). The received-mon index into the host party is
        host_cursor % PARTY_SIZE (partnerCursorPosition = recv[0][1] + PARTY_SIZE, indexed %
        PARTY_SIZE in TradeMons / CheckValidityOfTradeMons, trade.c:1654/trade_scene.c:2534).

        If more trades remain, re-arm a fresh round (S4_PARTY) - the wireless link
        stays up and CB2_CreateTradeMenu re-runs BufferTradeParties (trade.c:935; trade_scene.c:2752
        SetMainCallback2(savedCallback==CB2_StartCreateTradeMenu)). If this was the last trade, enter
        LEAVE mode (cancel-to-leave) instead of finishing here - we leave by selecting CANCEL once the
        host's fresh party exchange settles."""
        # Record the S7 invariant for tests: READY_FINISH must have been emitted before this commit.
        # (_reset_round_state below clears _finish_sent for the next round, so capture it here.)
        self._finish_sent_at_last_commit = self._finish_sent
        self.commits += 1
        received = None
        offered_slot = self.offered_slots[self.round]
        if self.host_cursor is not None:
            idx = self.host_cursor % PARTY_SIZE
            off = idx * monmod.PARTY_MON_SIZE
            received = monmod.Mon(bytes(self._host_party[off:off + 100]))
            self.received_mon = received                     # back-compat: last received
            self.received_mons.append(received)
            self.info("Trade confirmed.")
            self.log(f"RECEIVED (trade {self.round + 1}/{self.trades}): {received.describe()}")
            # LOCAL party swap (mirror TradeMons): the received mon lands in our offered slot, so the
            # NEXT round's re-staged party reflects it - exactly like the real gPlayerParty.
            self.party[offered_slot] = received
        self._offered.add(offered_slot)
        self.round += 1
        # Each committed trade reaches S8_DONE (recorded in state_history even when the next round
        # re-arms to S1_LINK in the same tick). This is the per-round commit marker.
        self.state = S8_DONE

        # [barrier (c)] post-trade SAVE barrier chain [trade_scene.c:2566-2725, REVISION>=0xA]: after
        # CONFIRM_FINISH the child runs a SEQUENCE of CHILD-INITIATED SetLinkStandbyCallback() barriers
        # (case 1, 41, 43, 5, and the case-8 loop-to-menu). Arm it so the engine drives the chain right
        # after the commit, BEFORE the next round's exchange / cancel-to-leave. The chain ends when the
        # host stops participating in barriers (SaveChainHost finishes; or MockHost re-exchanges, which
        # clears _save_barriers in feed_in_frame when its REQ/block arrives).
        self._save_barriers = True
        self._save_settle = 0
        self._save_started = False       # first save round prompt; subsequent rounds paced (SAVE_BARRIER_GAP)
        self._save_round_wait = 0

        if self.round < self.trades:
            self._arm_next_round()
        else:
            # all configured trades complete: do NOT set done; cancel-to-leave.
            self.leaving = True
            self.log(f"all {self.trades} trade(s) committed -> entering cancel-to-leave")
            self.info(f"All {self.trades} trade(s) complete; cancelling to leave.")
            self._arm_leave_round()

    def _reset_round_state(self):
        """Reset all per-round host-party collection + send-staging trackers so the NEXT trade
        replays the full BufferTradeParties exchange (trade.c:935 re-runs it on every menu entry).
        Re-stages OUR party blocks from the CURRENT (post-swap) self.party (mirrors the real
        gPlayerParty being re-streamed).

        DELIBERATELY does NOT clear self._lp_sent: the LinkPlayerBlock is a SESSION one-shot
        (exchanged once at entry, Task_PlayerExchange [link_rfu_2.c:1813-1900]; gReceivedRemoteLinkPlayers
        latches TRUE [1879] and is never cleared on the trade path). Clearing it every round would
        resend the LinkPlayer as party block #1 on trades 2..6 (and the cancel-to-leave round),
        shifting the party by one and dropping party pair #3 (gPlayerParty[4..5]) - a previously observed bug.
        BufferTradeParties [trade.c:1444-1542] re-streams ONLY the party on menu re-entry."""
        self._party_sent = 0
        self._party600 = monmod.build_player_party(self.party)
        self._party_blocks = monmod.party_blocks(self._party600)
        # host_link_player is the host's identity (stable across rounds) - keep it. The host re-runs
        # BufferTradeParties each round; its LinkPlayer block arrives first and is skipped (already
        # set), then the 3 party blocks land into a freshly-zeroed buffer. We reset the party buffer
        # + counters (re-collect the post-swap host party) but NOT the identity.
        self._host_party = bytearray(monmod.PARTY_MON_SIZE * PARTY_SIZE)
        self._host_party_blocks = 0
        self.host_cursor = None
        self._selected = False
        # Phase M (menu re-entry) RE-RUNS the full BufferTradeParties (party x3 -> mail -> ribbons,
        # trade.c:935). The menu-live gate (_trade_menu_live) must therefore RE-WAIT for THIS round's
        # ribbons before we select a mon / pick CANCEL - else a stale _got_ribbons (latched in the
        # FIRST exchange, never cleared here) fires READY_TO_TRADE / REQUEST_CANCEL after only the 3
        # party blocks, DURING the host's BufferTradeParties (before it pulls mail/ribbons and enters
        # the menu). The host's Leader_ReadLinkBuffer isn't running yet, so it never latches our
        # partnerSelectStatus -> it waits for our select while we wait for BOTH_CANCEL -> deadlock.
        # (a previously observed bug: cancel-to-leave fired before the host's mail+ribbons.)
        self._got_ribbons = False
        self._bt_settle = 0
        self._anim_wait = None
        self._finish_sent = False
        self._pending_confirm = False
        self._confirmed = False
        self._cancel_wait = None
        # the per-round one-shot soft initiates re-arm each round (the menu-entry + scene-seam barriers
        # fire once per trade); the save-chain (_save_barriers) is driven by the commit, not here.
        self._barrier_initiated_menu = False
        self._barrier_initiated_seam = False

    def _arm_next_round(self):
        """Re-arm for the next trade: reset per-round state and await the host's fresh party
        exchange (state back to S1_LINK -> S4_PARTY once the 3 host party blocks land again)."""
        self._reset_round_state()
        self.trade_slot = self.offered_slots[self.round]
        self.state = S1_LINK
        self.log(f"-> next trade {self.round + 1}/{self.trades}, offering slot {self.trade_slot}")

    def _arm_leave_round(self):
        """After the LAST trade, re-arm for one more menu entry (host re-runs BufferTradeParties),
        but with self.leaving set: the selection guard then emits REQUEST_CANCEL instead of
        READY_TO_TRADE once the party exchange settles (mirroring the human picking CANCEL after
        landing back in the menu)."""
        self._reset_round_state()
        self.state = S1_LINK

    # ---- CHILD-INITIATED standby barriers [link_rfu_2.c:1566-1573] -----------
    def _sustain_standby(self, count, emits_attr, regap_attr):
        """Emit READY_EXIT_STANDBY `count` as a bounded burst, RE-ARMED across a SAVE_BARRIER_GAP idle gap,
        so a FRESH count keeps reaching the host (the leader waits silently for it) until it completes the
        round - without flooding. The caller stops calling this once the host completes (barrier.host_count
        advances past `count`). Mirrors the save chain's sustain; fixes the live seat-phase comms error
        where a one-shot post-seat burst gave up and the host stuck waiting."""
        emits = getattr(self, emits_attr)
        if emits < WARP_STANDBY_EMITS:
            setattr(self, emits_attr, emits + 1)
            setattr(self, regap_attr, 0)
            return rfu.exit_standby_words(count)
        regap = getattr(self, regap_attr) + 1     # burst delivered (+ retransmitting); idle, then re-arm
        setattr(self, regap_attr, regap)
        if regap >= SAVE_BARRIER_GAP:
            setattr(self, emits_attr, 0)
            setattr(self, regap_attr, 0)
        return [0] * 7

    def _run_save_chain(self):
        """The post-trade SAVE barrier chain [trade_scene.c:2566-2725, REVISION>=0xA, CB2_SaveAndEndTrade]:
        after CONFIRM_FINISH the host runs ~5-6 SetLinkStandbyCallback barriers (cases 1/41/43/5/8 + the
        evolution-check) INTERLEAVED WITH ITS REAL SAVE (LinkFullSave_WriteSector). The child CHILD-INITIATES
        each standby round (reference captures: counts 5..10) and completes it on the host's mp0 echo (_on_host_standby).

        The host's save WRITES pace the barriers 0.3-1.8s apart (reference captures), so the host goes QUIET for >1.5s
        between rounds. The chain must therefore END only when the host RE-EXCHANGES (returns to the trade
        menu and re-pulls the party - Phase M; `host_reexchange` clears _save_barriers in feed_in_frame), NOT
        on a short quiet window. (Previously observed: ending on barriermod.IDLE_TIMEOUT (90f/1.5s) fired during a normal
        save pause - we did ONE save round then bailed -> the host stuck on "Saving..." (waiting for our next
        count) -> rolled the trade back.) SAVE_CHAIN_TIMEOUT is only the dead-host
        safety net (well above any real inter-barrier pause). Returns True while the chain runs (quiescent)."""
        if not self.barrier.active:
            # between rounds: start the next standby round, OR end the chain only if the host has truly
            # vanished (the dead-host safety net; the NORMAL end is host_reexchange in feed_in_frame).
            if self._save_settle > SAVE_CHAIN_TIMEOUT:
                self._save_barriers = False
                self.log(f"save-chain: host vanished for >{SAVE_CHAIN_TIMEOUT}f -> chain done (safety net)")
                return False
            # Initiate the next round IMMEDIATELY once the host completed the current one (barrier IDLE).
            # No artificial pacing: the host (leader) is ALREADY paced by its real save writes, and we
            # complete each round only on its mp0 echo - so we follow the host's cadence exactly. [The old
            # SAVE_BARRIER_GAP inter-round wait added ~1s/round (~6s) that made the host wait on us ("host
            # expected us sooner"); it was a band-aid for the race that the barrier re-broadcast guard
            # (_on_host_standby: ignore count < local_count) now fixes properly. With the adaptive-RTO
            # bootstrap clearing the bufferbloat, the save now runs at the native-Pia reference capture's ~1s/round.]
            self._save_started = True
            self.barrier.initiate(barriermod.STANDBY)
        return True

    def _advance_timers(self):
        """Advance the WALL-CLOCK trade countdowns by ONE VBlank: the [S7] post-START_TRADE animation
        timer -> READY_FINISH_TRADE, and the [S6] invalid-mon timer -> READY_CANCEL_TRADE. Driven from
        tick() (the normal/ungated path) AND from poll_send_done() when the Pia send-window is gated -
        exactly one of those runs per VBlank, so a countdown never double-advances. Sets _pending_push;
        the actual emission happens in tick() (the _pending_push block) once the window reopens.

        These are real-time timers (the ~32s/1935-frame DoTradeAnim, the 180-frame invalid-mon wait),
        so they MUST tick every VBlank. Leaving them inside tick() alone gated them behind the
        send-window: at the trade finish the window is full ~95% of VBlanks, so the anim timer advanced
        only ~5% as fast (~10 min instead of 32s) and READY_FINISH_TRADE was never sent -> the host sat
        forever on "Take good care of <mon>!" awaiting our finish. [3rd instance of the
        engine-state-gated-behind-emission class; cf. the block HOLD->DONE pump below.]"""
        if self._cancel_wait is not None:
            if self._cancel_wait > 0:
                self._cancel_wait -= 1
            else:
                self._cancel_wait = None
                self._pending_push = linkcmd_block(READY_CANCEL_TRADE)
                self.log("-> READY_CANCEL_TRADE (after 180f)")
        if self._anim_wait is not None:
            if self._anim_wait > 0:
                self._anim_wait -= 1
            else:
                self._anim_wait = None
                self._pending_push = linkcmd_block(READY_FINISH_TRADE)
                self._finish_sent = True
                self.info("Confirming trade...")
                self.log("-> READY_FINISH_TRADE")
                # early-arrival guard: if CONFIRM_FINISH already landed, run the deferred commit now
                # that READY_FINISH is on its way (keeps the FSM order S7 -> commit deterministic).
                if self._pending_confirm:
                    self._pending_confirm = False
                    self._commit()

    def poll_send_done(self):
        """Window-gated STATE pump: when the Pia send-window is full we cannot EMIT a slot this
        VBlank, but per-frame engine STATE must still advance. Two kinds:
          1. the wall-clock trade countdowns (_advance_timers) - so READY_FINISH/READY_CANCEL still
             fire on time (the trade-finish stall: the host waits on our READY_FINISH);
          2. an in-flight block send's HOLD -> DONE on the host's reflection - the real RFU
             SendLastBlock runs every VBlank regardless of any send buffer; gating the sender's STATE
             was the 2/3 party-block DEADLOCK (the sender stayed `done==False`, so _on_req dropped the
             host's next SEND_BLOCK_REQ -> the next party block was never sent) [native-Pia reference capture].
        The HOLD tick is idempotent (never advances the STREAM cursor, so no fragment is skipped); the
        held fragment is already in the reliable window + retransmitted there, so discarding tick()'s
        re-send words loses nothing. tick() returns early at the sender block BEFORE its own
        _advance_timers, so calling _advance_timers here AND self.tick() does not double-advance."""
        self._advance_timers()
        if self.sender is not None and self.sender.state == block.HOLD:
            self.tick()        # ticks ONLY the sender (returns early); emitted words discarded

    # ---- emit (one slot per VBlank) ----------------------------------------
    def tick(self):
        ack = self.rx.peers[1]          # the host's reflection of our block = wire ACK

        if self.sender is not None:
            words = self.sender.tick(ack)
            if self.sender.done:
                self.sender = None
                # a cancel block has fully streamed out [S5/S6 cancel / cancel-to-leave].
                if self._cancel_after_send and not self.done:
                    self._cancel_after_send = False
                    self.state = S_CANCEL
                    if self.leaving:
                        # Graceful cancel-to-leave. Do NOT finish on send; keep the
                        # link alive (idle keepalive / barrier replies) until the host echoes
                        # *_CANCEL (_on_linkcmd flips done + left_gracefully). This is a graceful
                        # cancel, not a hard stop.
                        self.log("REQUEST_CANCEL sent -> awaiting host *_CANCEL echo")
                    else:
                        # a mid-trade abort (invalid slot / decline / invalid mon): finish now,
                        # matching CB_HandleTradeCanceled -> CB_InitExitCanceledTrade -> exit
                        # (trade.c:2094-2132).
                        self.done = True
                        self.log("cancel block sent -> S_CANCEL (leaving)")
            return words

        # [barrier (d)] cancel-exit standby [trade.c:2117-2132]. After a BOTH_CANCEL the child stands by
        # ONE last time before returning to the field. Stay QUIESCENT (emit only the 0x6600) until the
        # barrier passes (host echo, or the offline watchdog), THEN finish. This unblocks a strict-ROM
        # host parked in the leader branch at CB_INIT_EXIT_CANCELED_TRADE's standby.
        if self._cancel_barrier_active:
            if self.barrier.active:
                return self.barrier.want_emit() or [0] * 7   # never return None (idle while quiescent)
            self._cancel_barrier_active = False
            # The cancel-exit standby (count=11) passed. The host now RETURNS TO THE FIELD
            # (CB_ExitCanceledTrade -> CB2_ReturnToFieldFromMultiplayer -> FieldCB_ReturnToFieldWireless-
            # Link -> Task_ReturnToFieldRecordMixing) and does a SECOND SetLinkStandbyCallback (count=12)
            # at case 0, then BLOCKS ON A BLACK SCREEN at case 1 - WarpFadeInScreen runs only once
            # IsLinkTaskFinished() [field_fadetransition.c]. That standby completes only when WE (child)
            # send our matching count=12, so we MUST child-initiate a SECOND post-cancel standby here.
            # Skipping it leaves the host faded-to-black forever (a previously observed bug; the reference
            # captures both show two child-initiated post-cancel standbys c=11,c=12 then host-led CLOSE c=13). Arm barrier (e).
            self._return_field_barrier_active = True
            self.barrier.initiate(barriermod.STANDBY)
            self.log("barrier (e): INITIATE return-to-field sync standby [field_fadetransition.c "
                     "Task_ReturnToFieldRecordMixing case 0 -> SetLinkStandbyCallback; host black-screens "
                     "at case 1 until we complete it]")

        # [barrier (e)] return-to-field sync standby (count=12). The host is faded-to-black at
        # Task_ReturnToFieldRecordMixing case 1 (IsLinkTaskFinished -> WarpFadeInScreen) until this
        # child-initiated round completes. Stay QUIESCENT (emit only the 0x6600) until the host echoes our
        # count (it reaches case 0 ~1s after the map load - well within INITIATE_TIMEOUT; reference capture ~1.5s) OR
        # the offline watchdog releases it, THEN hand off to the post-cancel overworld tail.
        if self._return_field_barrier_active:
            if self.barrier.active:
                return self.barrier.want_emit() or [0] * 7   # never return None (idle while quiescent)
            self._return_field_barrier_active = False
            self.done = True
            # Do NOT vanish here: re-arm the OVERWORLD held-keys + keep the barrier responder LIVE so we
            # emit the 0xBE00 keepalive and answer the host's READY_CLOSE_LINK (0x5F00) round instead of
            # disconnecting before it. `done` still latches (the trade/cancel + return-
            # to-field LOGIC is complete) - the orchestrator runs the overworld leave tail and lets the
            # HOST lead the walk-out / sever ('D').
            self._post_cancel_overworld = True
            self.log("barrier (e): return-to-field standby passed -> done (post-cancel overworld; held-keys "
                     "re-armed, awaiting host READY_CLOSE_LINK)")

        # POST-CANCEL OVERWORLD leave tail: keep answering the host's barriers (its READY_CLOSE_LINK 0x5F00
        # round, or a residual standby) so its teardown completes; between barriers emit IDLE so sim.py's
        # held-keys engine (0xBE00 keepalive + EXIT_ROOM 0x17) takes over.
        if self._post_cancel_overworld and self.barrier.active:
            return self.barrier.want_emit() or [0] * 7   # never return None (idle while quiescent)

        # [barrier (c)] post-trade SAVE barrier chain [trade_scene.c:2566-2725]. Driven right after the
        # commit, BEFORE any next-round exchange / cancel-to-leave. While the chain runs the engine is
        # QUIESCENT (emits only the 0x6600). Reached only when no block send owns the slot (priority 1
        # above) - a barrier and a block never coexist on the wire.
        if self._save_barriers:
            if self._run_save_chain():
                # never return None: during the inter-round pace (barrier idle) want_emit() is None;
                # emit an idle slot so eng.tick() always yields a valid 7-int run [post-trade crash].
                return self.barrier.want_emit() or [0] * 7

        # WALL-CLOCK countdowns ([S7] anim -> READY_FINISH, [S6] invalid-mon -> READY_CANCEL). These
        # must advance EVERY VBlank, so they live in _advance_timers, which poll_send_done ALSO drives
        # on window-gated VBlanks (see there) - otherwise the ~32s anim timer crawls behind the
        # send-window and READY_FINISH is never sent (the host parks on "Take good care of <mon>!").
        self._advance_timers()

        # [barrier (b)] menu->scene seam standby [trade.c:2159-2166, CB_WaitToStartRfuTrade]: on
        # receiving START_TRADE the child enters CB_WAIT_TO_START_RFU_TRADE and calls
        # SetLinkStandbyCallback() ITSELF before the scene/anim runs. INITIATE the barrier here (emit
        # our 0x6600 on idle frames) so a strict-ROM host parked at this seam (leader branch waiting
        # for the child) is unblocked - the deadlock fix. Soft initiate (same rationale as (a)): the
        # anim countdown still runs so a non-participating host (MockHost) does not stall; the barrier
        # completes reactively when a participating host echoes our count.
        if self._anim_wait is not None and not self._barrier_initiated_seam:
            self._barrier_initiated_seam = True
            self.barrier.initiate(barriermod.STANDBY)
            self.log("barrier (b): INITIATE menu->scene-seam standby [trade.c:2159-2166]")

        # ([S7] animation countdown -> READY_FINISH and [S6] invalid-mon -> READY_CANCEL now run in
        # _advance_timers above, so they tick every VBlank even when the send-window is gated. The
        # local TradeMons swap happened conceptually at CB2_UpdateLinkTrade:2533; we capture the
        # received mon at _commit. READY_FINISH is staged into _pending_push and streamed below.)

        # [barrier (a)] trade-menu entry standby - DISABLED (fixes a count=4 flood).
        # We had assumed a menu-entry standby here, but the reference capture has NO standby between the party
        # exchange and START_TRADE: the real sequence is READY_TO_TRADE -> host SET_MONS_TO_TRADE ->
        # INIT_BLOCK -> host START_TRADE, and the FIRST trade-dance standby (count=4) comes AFTER
        # START_TRADE (handled by barrier (b), the menu<->scene seam). Initiating count=4 here (the
        # warp-quiesce reactive mirror left local_count=4 after the post-seat count=3 round) fired it
        # ONE round ahead of the host (still at count=3); the host's recv gate (count==cur) ignored it,
        # the round never completed, and the child-initiated barrier emitted count=4 every VBlank -> ~84
        # frames flooded the host's buffer -> Communication error at the "Communicating..." standby.
        # The host drives no standby at menu entry, so we must NOT initiate one; we idle (waiting for the
        # host's SET_MONS) and let barrier (b) initiate count=4 after START_TRADE.


        # [S5] selection: once the trade menu is live, either select our next mon OR (after the last
        # trade) cancel-to-leave. The real trigger is a menu A-press on a slot that passes
        # CanTradeSelectedMon -> SetReadyToTrade (trade.c:1905-1908), or selecting the CANCEL option
        # -> CB_ProcessCancelTradeInput case 0 -> QueueLinkData(LINKCMD_REQUEST_CANCEL, 0)
        # (trade.c:2049). Autonomous stand-in: fire once the menu is live (_trade_menu_live).
        if (not self._selected and self.state in (S4_PARTY,)
                and self._trade_menu_live() and self._pending_push is None):
            self._selected = True
            # ENTRY: the party exchange is fully done and we are about to select a mon -> the trade
            # menu is live (CB2_CreateTradeMenu reached). The seat barrier (P2) + standby window #2
            # (P3) are behind us; mark the one-shot entry complete and hand off to the trade FSM. On
            # trades 2..6 this is already P5 (complete), so on_trade_menu_live is a no-op (the entry
            # never re-fires - the post-trade loop re-enters CB2_StartCreateTradeMenu, not the seat).
            self.entry.on_trade_menu_live()
            if self.leaving:
                # All configured trades are done. We are back at the live trade
                # menu (the host re-ran BufferTradeParties); select CANCEL -> REQUEST_CANCEL 0xEEAA.
                self.info("Cancelling the trade menu...")
                self.log("-> REQUEST_CANCEL (leaving: CANCEL selected) [trade.c:2049]")
                self._pending_push = linkcmd_block(REQUEST_CANCEL)
                self.requested_cancel = True
                self.cancelled = True
            elif self._is_valid_slot(self.trade_slot):
                self.state = S5_SELECT
                self._pending_push = linkcmd_block(READY_TO_TRADE, self.trade_slot)
                self.info("Offered our Pokémon; waiting on the host.")
                self.log(f"-> READY_TO_TRADE cursor={self.trade_slot} "
                         f"(trade {self.round + 1}/{self.trades})")
            else:
                self.log(f"slot {self.trade_slot} fails CanTradeSelectedMon -> REQUEST_CANCEL")
                self.info(f"Cannot trade slot {self.trade_slot}; cancelling to leave.")
                self.state = S5_SELECT
                self._pending_push = linkcmd_block(REQUEST_CANCEL)
                self.requested_cancel = True
                self.cancelled = True

        if self._pending_push is not None:
            buf = self._pending_push
            self._pending_push = None
            # If this push is a cancel-to-leave opcode (REQUEST_CANCEL / READY_CANCEL_TRADE), arm
            # the cancel-after-send latch: once the block has fully streamed out we route to S_CANCEL
            # and finish - matching CB_HandleTradeCanceled / CB_InitExitCanceledTrade -> exit
            # (trade.c:2094-2132). Deferring until the send completes lets the host actually receive
            # the cancel block before we leave (a graceful cancel, not a hard stop).
            pushed_cmd = int.from_bytes(buf[0:2], "little")
            if pushed_cmd in (REQUEST_CANCEL, READY_CANCEL_TRADE):
                self._cancel_after_send = True
                self.cancelled = True
            return self._begin_send(buf).tick(self.rx.peers[1])   # fresh peer-1 after reset

        # WARP-QUIESCE standbys (fixes the host hanging at trade-room entry on a black screen). Between the
        # LinkPlayer exchange (established) and the seat (host_in_seat), the host WAITS for our
        # READY_EXIT_STANDBY before pulling the trainer card and before streaming SEND_HELD_KEYS - the
        # reference capture's guest emits count=0 (post-LinkPlayer) then count=1 (post-card), mutual barriers the host gates
        # on. We drive the count PHASE-wise (0 until the card is pulled, 1 after) rather than via the
        # shared barrier's auto-count, whose reactive mirror the host's repeated echoes would reset. The
        # sim emits these one per VBlank (free-run); the host streams idle keepalives while it waits.
        if self.established and not self._host_in_seat:
            wcount = 0 if not self.entry.card_supplied else 1
            # BOUNDED burst (NOT a flood): emit the round's count up to WARP_STANDBY_EMITS NEW frames,
            # then IDLE and wait - reliable retransmit keeps re-sending the queued burst until the host
            # acks it, so the host gets our standby without us jamming the window with hundreds of frames
            # (which previously blocked the card send -> black screen). Return idle DIRECTLY (not falling
            # through to the priority-5 barrier, which would re-flood by mirroring the host's echoes).
            if wcount == 0:
                if not self._barrier_initiated_warp1:
                    self._barrier_initiated_warp1 = True
                    self.log("warp#1: emitting post-LinkPlayer READY_EXIT_STANDBY count=0 (await host card)")
                if self._warp1_emits < WARP_STANDBY_EMITS:
                    self._warp1_emits += 1
                    return rfu.exit_standby_words(0)
            else:
                if not self._barrier_initiated_warp2:
                    self._barrier_initiated_warp2 = True
                    self.log("warp#2: emitting post-card READY_EXIT_STANDBY count=1 (await host seat)")
                if self._warp2_emits < WARP_STANDBY_EMITS:
                    self._warp2_emits += 1
                    return rfu.exit_standby_words(1)
            return [0] * 7              # burst delivered/in-flight; idle + wait (no window-jamming flood)

        # POST-SEAT warp into the trade SCENE (fixes a black screen after both players sit). Once WE have sat
        # (note_self_seated) and we are still in the seat phase, emit the two remaining standby rounds -
        # count=2 then count=3 - which the reference capture's guest drives AFTER both players are READY and BEFORE the
        # host pulls the party (BufferTradeParties). A short keepalive delay first lets our READY land on
        # the wire (the held-keys slot) before we switch to the standby slot. Bounded bursts (like #1/#2);
        # reliable retransmit delivers them; then idle -> held-keys keepalive until the host's party pull
        # latches seat_phase_over and ends this phase.
        if self.established and self._self_seated and not self.entry.seat_phase_over:
            if self._post_seat_wait > 0:
                self._post_seat_wait -= 1
                return [0] * 7         # still letting our READY + keepalives go out before count=2
            # The two post-seat standbys (count=2 then count=3, Task_StartWirelessTrade) are MUTUAL
            # barriers the host (leader) waits SILENTLY for [Rfu_LinkStandby, link_rfu_2.c:1577-1591].
            # We must SUSTAIN each count until the host COMPLETES it (its own mp0 0x6600, latched in
            # barrier.host_count >= N), then advance - NOT fire a one-shot burst and give up. (Live
            # comms-error root cause: the old bounded burst quit after WARP_STANDBY_EMITS, so when we
            # sent count=3 while the host was still finishing count=2 (recv gate rejected it) and our
            # burst then ended, the host sat silently waiting for a fresh count=3 forever. Same sustain
            # pattern as the post-trade save chain.)
            hc = self.barrier.host_count or 0
            if hc < 2:                          # warp#3: drive count=2 until the host completes it
                if not self._barrier_initiated_warp3:
                    self._barrier_initiated_warp3 = True
                    self.log("warp#3: post-seat READY_EXIT_STANDBY count=2 (sustained until host completes)")
                return self._sustain_standby(2, "_warp3_emits", "_warp3_regap")
            if hc < 3:                          # warp#4: count=3 ONLY after the host did count=2; sustained
                if not self._barrier_initiated_warp4:
                    self._barrier_initiated_warp4 = True
                    self.log("warp#4: post-seat READY_EXIT_STANDBY count=3 (host reached count=2; "
                             "sustained until host completes)")
                return self._sustain_standby(3, "_warp4_emits", "_warp4_regap")
            return [0] * 7              # both post-seat bursts sent / waiting; idle + keepalive

        # Priority 5: standby / close-link barrier. Reached ONLY when no block send (priority 1),
        # animation/READY_FINISH push (2), selection push (3), or pending LINKCMD push (4) owns the
        # slot this VBlank - exactly the slot the engine would have idled. A barrier and a block
        # never coexist on the wire, so this cannot corrupt the rolling tag relative to a block send
        # [link_rfu_2.c:1553/1569/1586: the host only standbys when the queues are drained].
        bwords = self.barrier.want_emit()
        if bwords is not None:
            return bwords

        return [0] * 7                  # idle keepalive
