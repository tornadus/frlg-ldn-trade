#!/usr/bin/env python3
"""frlgtrade - FireRed/LeafGreen trade simulator (JOINER) over the LDN bridge.

Joins a real FRLG console's link session as the wireless CHILD and performs 1..6 sequential trades,
injecting chosen .pk3 mons and saving each received mon as a .pk3.

Supply 1..6 party .pk3/.ek3 files (gPlayerParty slots 0..5). --trades N (1..6, default 1) sets how
many sequential trades to perform; --slots picks which OUR slot is offered each round (default:
ascending distinct slots from --slot, or [0..N-1] for the full-party swap). After the Nth trade the
sim leaves by selecting the trade-menu CANCEL option (REQUEST_CANCEL 0xEEAA), a graceful
cancel-to-leave [trade.c:2049].

LIVE (needs the Switch, root, and the ldn/trio/netlink deps):
    sudo -E python3 frlgtrade.py --live --password PASS dummy.pk3 trademon.pk3 -o received.pk3
    sudo -E python3 frlgtrade.py --live --trades 6 a.pk3 b.pk3 c.pk3 d.pk3 e.pk3 f.pk3

OFFLINE self-check (replays a captured host stream through the full RX stack - no Switch):
    python3 frlgtrade.py --replay capture.jsonl dummy.pk3 trademon.pk3
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from frlgsim import crypto as cryptomod, mon as monmod, linkplayer, trade, sim as simmod  # noqa
from frlgsim import transport as tmod, linkstate as lsmod  # noqa: E402
from frlgsim import barrier as lsmod_barrier, pia_connect  # noqa: E402


_START = time.monotonic()   # session origin for the elapsed-time stamp on every log line


class _Log:
    """Two-level console logger. Calling it prints a DETAIL line (only with --verbose); .info()
    prints a clean, identifier-free MILESTONE line (only WITHOUT --verbose). So a default run
    narrates the session's state changes with no personal data, while --verbose gives the full
    wire-level trace. `prefix` is prepended to detail lines (the trade engine uses "  [trade]").
    Every line is stamped with seconds since session start, so a pause between milestones (e.g. the
    host taking its time to walk into the trade room) is visible as the gap between two stamps."""

    def __init__(self, verbose, prefix=""):
        self.verbose = verbose
        self.prefix = prefix

    def _ts(self):
        return f"[{time.monotonic() - _START:7.1f}s]"

    def __call__(self, *a):
        if self.verbose:
            print(self._ts(), self.prefix, *a) if self.prefix else print(self._ts(), *a)

    def info(self, *a):
        if not self.verbose:
            print(self._ts(), *a)


def parse_slots(spec, trades, party_len):
    """--slots "a,b,c" -> a validated list of 0-based party indices (len==trades, distinct, in-range).
    Returns None when spec is empty (the engine then derives the default from --slot)."""
    if not spec:
        return None
    try:
        slots = [int(s) for s in spec.split(",") if s != ""]
    except ValueError:
        raise SystemExit(f"--slots must be a comma list of integers, got {spec!r}")
    if len(slots) != trades:
        raise SystemExit(f"--slots must have {trades} entries (== --trades), got {len(slots)}")
    if len(set(slots)) != len(slots):
        raise SystemExit(f"--slots must be distinct (a slot can't be offered twice): {slots}")
    if any(not 0 <= s < party_len for s in slots):
        raise SystemExit(f"--slots must each be 0..{party_len - 1} (party size): {slots}")
    return slots


def make_engine(args, lg):
    party = [monmod.Mon.from_file(p) for p in args.party]
    for i, m in enumerate(party):
        lg(f"  party slot {i}: {m.describe()}")
    lg.info(f"Loaded {len(party)} party Pokémon (offering slot {args.slot + 1}).")
    # Validate the trade count against the party: N distinct slots need N mons; a
    # full-party swap (N=6) needs a full 6-mon party.
    if args.trades > len(party):
        raise SystemExit(f"--trades {args.trades} needs at least {args.trades} party mons "
                         f"(distinct slot per round); supplied {len(party)}")
    offered_slots = parse_slots(args.slots, args.trades, len(party))
    lp = linkplayer.LinkPlayer(
        name=args.ot,
        version=linkplayer.VERSION_FIRE_RED if args.version == "firered"
        else linkplayer.VERSION_LEAF_GREEN,
    )
    elog = _Log(lg.verbose, "  [trade]")   # engine detail lines get the "  [trade]" tag
    # anim_delay None -> the engine uses DEFAULT_ANIM_FRAMES (the wire-measured wireless DoTradeAnim
    # duration); --anim-delay overrides it (mainly for fast offline replays).
    eng = trade.TradeEngine(party, trade_slot=args.slot, link_player=lp, mpid=args.self_id,
                            anim_delay=args.anim_delay, decline=args.decline,
                            trades=args.trades, offered_slots=offered_slots,
                            refuse_partner_deoxys_mew=args.refuse_illegit,
                            trust_pia=args.trust_pia, log=elog)
    lg(f"  seat=RIGHT (Follower / mpId={eng.mpid}); trades={eng.trades}, "
       f"offered_slots={eng.offered_slots}")
    return eng


def run_live(args, lg):
    lg(f"[live] scanning for FRLG LDN network (nickname={args.ot})...")
    comm_id = int(args.comm_id, 16) if args.comm_id else None
    password = bytes.fromhex(args.password) if args.password else None   # None -> built-in
    t = tmod.LiveTransport(password=password, nickname=args.ot, keys_path=args.keys,
                           local_comm_id=comm_id, phyname=args.phy, log=lg).start()
    pc = cryptomod.PiaCrypto(t.ssid)
    engine = make_engine(args, lg)
    # Pia CONNECTION layer (S0): Net 0x11->0x12, Session(13) join, RTT keepalive. WITHOUT this the
    # host never registers us as a peer (no "OK"); the sim must NOT emit trade traffic or sit down
    # until the host confirms the connection [frlgsim/pia_connect.py; wiki Pia 6.32+]. The MACs are
    # the Pia connection GUIDs, learned from the LDN participant list.
    if not t.our_mac or not t.host_mac:
        lg(f"[live] WARNING: MAC(s) not resolved from the participant list "
              f"(us={t.our_mac and t.our_mac.hex()} host={t.host_mac and t.host_mac.hex()}); "
              f"the Session join may be rejected.")
    conn = pia_connect.ConnectionManager(
        our_mac=t.our_mac or b"\x00" * 6, host_mac=t.host_mac or b"\x00" * 6,
        our_ip=t.our_ip, host_ip=t.host_ip, player_name=args.ot,
        random4=os.urandom(4), log=lg)
    # Held-keys overworld link-state engine: keepalive (0xBE00 EMPTY) every idle VBlank, sit at
    # the RIGHT seat (mpId 1), then cancel-to-leave after the configured trade(s). self_id is
    # asserted == 1 (the joiner / RIGHT seat) [frlgsim/linkstate.py; trade.c:1816].
    lstate = lsmod.LinkState(self_id=args.self_id, log=lg)
    parent_pid = bytes.fromhex(args.parent_pid) if args.parent_pid else t.parent_pid
    if parent_pid:
        src = "override" if args.parent_pid else "beacon idx20-21"
        lg(f"[live] emulator connect: will send 'C' with parent RFU id {parent_pid.hex()} "
              f"({src}). The host's 'A' (0x41) accept confirms it; if no 'A' arrives, try "
              f"--parent-pid with the struct id-field value logged above.")
    else:
        lg("[live] emulator connect: no parent RFU id (beacon too short / not parsed) -> NOT "
              "sending a 'C' frame. Pass --parent-pid to force one.")
    s = simmod.Sim(t, pc, engine, t.our_ip, t.host_ip, conn=conn, compress=args.compress,
                   linkstate=lstate, parent_pid=parent_pid, capture_path=args.capture, log=lg)
    if args.capture:
        lg(f"[live] capturing every Pia datagram (both dirs) -> {args.capture} "
              f"(decrypt/analyse offline afterward)")
    lg(f"[live] joined LDN; awaiting the host's Pia connection handshake "
          f"(Net 0x11 -> Session join -> confirm). NOT trading until the host confirms us.")
    lg(f"[live] configured trades={args.trades} (cancel-to-leave after the final trade)")
    period = 1.0 / 59.727
    # Sit at the RIGHT seat once the link is ESTABLISHED so our slot reaches PLAYER_LINK_STATE_READY
    # and the host's seat barrier (GetCableClubPartnersReady) can clear [overworld.c:2989-3000].
    #
    # Faithfulness: in the ROM the READY(0x16) one-shot is KeyInterCB_SetReady, installed by
    # SetInCableClubSeat inside Task_EnterCableClubSeat case 1 [cable_club.c:839; overworld.c:2951-2955]
    # - and SendKeysToRfu only emits it once gReceivedRemoteLinkPlayers is set [link_rfu_2.c:1069], i.e.
    # AFTER the LinkPlayer exchange. So we gate sit() on engine.established (gReceivedRemoteLinkPlayers:
    # both LinkPlayer blocks exchanged) - NOT on a blind timer. An earlier blind 120-frame fallback
    # fired sit() ~2s after Pia connect regardless of link progress, racing a tagged 0xBE00 READY into
    # an unestablished slot and faulting the host's childSendCmdId check; it is removed. Live residual:
    # the warp/seat transition itself is a local field task not on the wire, so we approximate it
    # with the establishment latch - the last wire-observable milestone before the seat.
    sat = exited = connect_announced = responded_exit = False
    announced_cancel = announced_close = announced_entry = announced_menu = False
    announced_established = False
    saved_commits = 0       # received mons already written to disk (save AT COMMIT, not just run-end)
    connect_ticks = 0
    leave_until = None
    close_until = None
    # Overworld leave tail: keep the link ALIVE (held-keys keepalive) while waiting for the HOST to lead
    # the walk-out and sever the link itself (graceful). The host's exit is human-paced (walk to the south
    # exit -> confirm-leave prompt -> EXIT_ROOM -> RunTerminateLinkScript -> CloseLink -> 'D'), so this is
    # generous - the loop ends sooner on the host's actual 'D' disconnect / READY_CLOSE_LINK. Going silent
    # BEFORE the host leads would trip its keepalive watchdog (LinkRfu_FatalError), so err long, not short.
    LEAVE_TAIL_S = 120.0
    try:
        while True:
            s.tick()
            # Save each received mon the INSTANT it commits (on CONFIRM_FINISH), not just at graceful
            # run-end: the post-trade tail (save chain / cancel / close) can stall or be Ctrl+C'd, and the
            # mon data is already valid at commit. Writing here means the received mon survives an
            # abrupt exit. save_received() is idempotent (re-writes all received).
            if engine.commits > saved_commits:
                saved_commits = engine.commits
                try:
                    n = save_received(engine, args, lg)
                    lg(f"[live] trade committed -> saved {n} received mon(s) to disk now "
                          f"(robust to an abrupt exit)")
                except Exception as e:                       # never let a save error kill the link tail
                    lg(f"[live] WARNING: could not save received mon at commit: {e}")
            # host REJECTED our join (recv-NI status != JOIN_GROUP_OK): bail cleanly instead of acking
            # forever then hanging on a UNI that never arrives.
            if getattr(s, "ni_rejected", False):
                lg("[live] ABORT: host rejected our join (NI status != JOIN_GROUP_OK) - leaving.")
                lg.info("Host rejected our join; leaving.")
                break
            # host closed the RFU link (emulator 'D'): the link is down, stop cleanly.
            if getattr(s, "host_disconnected", False):
                lg("[live] host closed the RFU link ('D' 0x44) - disconnecting.")
                break
            # --- S0 GATE: do NOTHING (no sit, no trade) until the host CONFIRMS the connection.
            # sim.tick() only emits trade Reliable once s.connected; here we likewise hold off the
            # seat/trade orchestration so we never "blow past" the host's connection confirmation.
            if not s.connected:
                connect_ticks += 1
                if connect_ticks % 120 == 0:
                    lg(f"[live] awaiting host connection: {connect_ticks}f, conn={conn.state}, "
                          f"host_var={'learned' if s._learned else 'unseen'}, "
                          f"rx_ok={s.rx_count} rx_decryptfail={s.rx_fail} "
                          f"protos_seen={dict(sorted(s.rx_protos.items()))} tx={s.tx_count}")
                time.sleep(period)
                continue
            if not connect_announced:
                lg(f"[live] Pia connection ESTABLISHED - host confirmed us "
                      f"(conn={conn.state} after {connect_ticks}f). Awaiting the emulator RFU "
                      f"connect/'A' + NI handshake + LinkPlayer exchange before sitting.")
                connect_announced = True
            if not announced_established and engine.established:
                announced_established = True
                lg("[live] RFU link ESTABLISHED (gReceivedRemoteLinkPlayers: both LinkPlayer "
                      "blocks exchanged) - held keys + sit are now armed.")
            # sit() (the held-keys READY 0x16 seat-down) is gated on the HOST itself SITTING - i.e. the
            # host emitting its own READY (0x16), engine.host_ready - NOT merely on it entering the room
            # (host_in_seat). Sitting on host_in_seat fired READY while the host's avatar was still
            # walking to its chair (FSM in 'Please wait') -> out-of-sequence READY faults the host's
            # cable-seat FSM immediately (observed as a comms error on trade-room load). Until host_ready we emit
            # EMPTY held-keys keepalive (host_in_seat armed the seat keepalive); we sit WITH the host so
            # GetCableClubPartnersReady sees both PLAYER_LINK_STATE_READY and clears.
            if not sat and engine.host_ready:
                lg("[live] host sat (READY 0x16) - sitting at the RIGHT seat (READY 0x16).")
                lstate.sit()
                engine.note_self_seated()   # arm the post-seat warp-into-scene standbys (count=2, count=3)
                sat = True
            # ENTRY-phase observability: report the union-room -> trade-center handshake.
            if not announced_entry and engine.entry.card_pulled:
                lg("[live] entry: host pulled our 100B trainer card (BLOCK_REQ_SIZE_100) - "
                      "supplied; this is the pre-trade card exchange (Task_ExchangeCards).")
                announced_entry = True
            if not announced_menu and engine.entry.complete:
                lg("[live] entry: complete (P0..P5) - trade menu is live; entering the trade FSM.")
                lg.info("Trade menu open; received the host's party.")
                announced_menu = True
            # Cancel-to-leave: once the trade/cancel LOGIC is done, do NOT disconnect
            # AND do NOT initiate the walk-out ourselves. LET THE HOST LEAD THE EXIT. Either player CAN
            # emit EXIT_ROOM (overworld.c:2701-2710 DPAD_DOWN at the south exit -> CreateConfirmLeave...
            # -> EXIT_ROOM(0x17) -> 2751 sPlayerLinkStates=EXITING_ROOM), but the HOST leading is cleaner:
            # the host runs its OWN RunTerminateLinkScript + CloseLink and SEVERS the link itself (a clean
            # 'D'), while we - a fake client - have no teardown FSM/scripts to drive (the host terminates
            # off its own EXITING_ROOM; RunTerminateLinkScript runs only if (player->isLocalPlayer), so it
            # never needs us to LEAD). Emitting EXIT_ROOM PROACTIVELY (the instant the cancel-exit standby
            # passes) hit the host mid-CB2_ReturnToFieldFromMultiplayer (field link FSM not re-established)
            # -> it couldn't process our EXITING_ROOM -> CheckRfuKeepAliveTimer -> LinkRfu_FatalError
            # (observed live). So we let the HOST lead: keep the link ALIVE (sim's 0xBE00 keepalive, re-armed by
            # _post_cancel_overworld + the barrier responder) and WAIT. BUT - the host's walk-out is a
            # MUTUAL handshake: when it walks out it broadcasts EXIT_ROOM and BLOCKS at
            # KeyInterCB_WaitForPlayersToExit ("escorted out... please wait") until ALL players are
            # EXITING_ROOM, so we MUST answer with OUR EXIT_ROOM (reactively, below) - silence hangs the host.
            if engine.done and not exited:
                lg("[live] trade(s) complete - returning to the overworld; keeping the link ALIVE "
                      "(held-keys keepalive + barrier) and letting the HOST lead the walk-out. Will answer "
                      "the host's EXIT_ROOM with ours, then mirror its READY_CLOSE_LINK / 'D'.")
                exited = True
                leave_until = time.monotonic() + LEAVE_TAIL_S
            # The host walked out (EXIT_ROOM 0x17) and is blocked waiting for ALL players to be EXITING_ROOM
            # [overworld.c:2962-2981]. RESPOND with OUR EXIT_ROOM (lstate.exit() emits 0x17 once, then EMPTY
            # keepalive) so the host marks us EXITING_ROOM -> CableClub_EventScript_DoLinkRoomExit ->
            # READY_CLOSE_LINK (c=13). This is the REACTIVE walk-out (NOT the premature proactive
            # EXIT_ROOM that faulted earlier - the host is now genuinely waiting for it).
            if engine.host_exiting and not responded_exit and lstate is not None:
                lg("[live] host is walking out (EXIT_ROOM 0x17, 'escorted out... please wait') - "
                      "responding with OUR EXIT_ROOM so both are EXITING_ROOM -> host closes the link.")
                lstate.exit()
                responded_exit = True
            # When the host issues READY_CLOSE_LINK (0x5F00) the responder mirrors it; answer briefly,
            # then disconnect (the close handshake is done - no need to wait out the full tail)
            # [trade_scene.c:2722-2725; trade.c:2117-2132; link_rfu_2.c:1460-1520].
            if engine.barrier.mode == lsmod_barrier.CLOSE:
                if not announced_close:
                    announced_close = True
                    close_until = time.monotonic() + 1.5
                    lg("[live] host issued READY_CLOSE_LINK (0x5F00) - answering, then disconnecting.")
                    lg.info("Closing the link...")
                if close_until is not None and time.monotonic() >= close_until:
                    break
            elif (exited and engine.barrier.mode == lsmod_barrier.STANDBY
                  and not announced_cancel):
                lg("[live] answering the host's cancel-side standby (0x6600) so its "
                      "cancel-to-leave completes.")
                announced_cancel = True
            if leave_until is not None and time.monotonic() >= leave_until:
                lg("[live] overworld leave tail elapsed without a host CLOSE - disconnecting.")
                break
            time.sleep(period)
    finally:
        s.close()          # flush the --capture .jsonl
        t.stop()
        lg.info("Link closed.")
    return engine


def run_replay(args, lg):
    print(f"[replay] feeding host IN stream from {args.replay} through the RX stack...")
    t = tmod.ReplayTransport.from_capture(args.replay)
    if not t.ssid:
        sys.exit("capture has no SSID (predates SSID logging) - cannot decrypt")
    pc = cryptomod.PiaCrypto(t.ssid)
    # the capture has a finite frame budget; the realistic 1935-frame anim would outlast it, so use
    # a small anim_delay for replay unless the user explicitly set --anim-delay. The early-arrival
    # guard keeps READY_FINISH before commit regardless of the value.
    if args.anim_delay is None:
        args.anim_delay = 5
    engine = make_engine(args, lg)
    s = simmod.Sim(t, pc, engine, t.our_ip, t.host_ip, log=lg)
    while not t.drained and not engine.done:
        s.tick()
    print(f"[replay] processed {s.rx_count} IN / emitted {s.tx_count} OUT datagrams")
    if engine.host_link_player:
        lg(f"[replay] host LinkPlayer reconstructed: {engine.host_link_player.name} "
           f"v0x{engine.host_link_player.version:04x}")
    print(f"[replay] host party blocks collected: {engine._host_party_blocks}/3")
    return engine


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("party", nargs="+", metavar="MON",
                    help="1..6 party mons, each a .pk3 or .ek3 file (gPlayerParty slots 0..5). The "
                         "documented default supplies 2: a kept mon (slot 0) and the trade mon "
                         "(slot 1).")
    ap.add_argument("-o", "--out", default="received.pk3",
                    help="save the received mon here (trades=1); for trades>1 this is a BASE/prefix "
                         "and each received mon is saved as <stem>_trade<k>_<species>.pk3")
    ap.add_argument("--out-size", type=int, choices=(80, 100), default=100,
                    help="received file size (100=party, 80=box)")
    ap.add_argument("--out-format", choices=("pk3", "ek3"), default="pk3",
                    help="received mon format: pk3=decrypted (opens in PKHeX), ek3=encrypted/raw")
    ap.add_argument("--slot", type=int, default=1,
                    help="party slot to offer on the FIRST round (default 1); the per-round default "
                         "list grows ascending from here (or [0..N-1] for a full-party swap)")
    ap.add_argument("--slots", default="",
                    help="explicit comma list of 0-based party slots to offer, one per trade "
                         "(len must == --trades, distinct, each < party size), e.g. --slots 0,2,4")
    ap.add_argument("--trades", type=int, default=1, choices=range(1, 7), metavar="N",
                    help="number of sequential trades to perform, 1..6 (default 1; 6 = swap both "
                         "entire parties). After the Nth trade the sim cancels-to-leave.")
    ap.add_argument("--self-id", type=int, default=1, choices=(1,),
                    help="wire mpId / gLocalLinkPlayerId (joiner = 1 = RIGHT seat; the only valid "
                         "value - mpId 0 is the host/parent) [trade.c:1816; link_rfu_2.c:1633-1638]")
    ap.add_argument("--ot", default="EMU", help="sim trainer / OT name (LinkPlayer)")
    ap.add_argument("--version", choices=("firered", "leafgreen"), default="leafgreen")
    ap.add_argument("--anim-delay", type=int, default=None,
                    help="frames to wait after START_TRADE before READY_FINISH "
                         f"(default {trade.DEFAULT_ANIM_FRAMES}, the wire-measured wireless "
                         "DoTradeAnim duration)")
    ap.add_argument("--decline", action="store_true",
                    help="decline at the confirm prompt (confirm-NO -> immediate READY_CANCEL, "
                         "graceful cancel-to-leave) [trade.c:2019-2023]")
    ap.add_argument("--refuse-illegit", action="store_true",
                    help="treat an offered Deoxys/Mew as PARTNER_MON_INVALID and cancel-to-leave "
                         "(the host's illegitimate-legend gate; legitimacy is not offline-decodable)"
                         " [trade.c:1965-1968]")
    ap.add_argument("--trust-pia", action=argparse.BooleanOptionalAction, default=False,
                    help="send each block fragment ONCE (fire-and-forget) instead of the console's "
                         "re-send-until-confirmed loop. Default OFF (faithful re-send): against the real "
                         "client, a block streams in 1-2s WITH aggressive re-sends (~1.5x) and completes; "
                         "trust_pia's send-once crawled (~0.1 frag/s) and never completed. trust_pia was a "
                         "workaround for the 'flood', but that was the RTT deadlock (now fixed). "
                         "--trust-pia re-enables send-once")
    ap.add_argument("--compress", action="store_true", help="zstd-compress OUT payloads")
    ap.add_argument("--parent-pid", default="",
                    help="(live) override the parent's RFU id (hex) for the emulator connect ('C') "
                         "frame [rfu_REQ_startConnectParent]. Default: extracted from the host's "
                         "beacon (the session-varying parent id). Pass e.g. 7036 to try the struct "
                         "id-field instead.")
    ap.add_argument("--verbose", action="store_true")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="join the real Switch")
    mode.add_argument("--replay", metavar="CAPTURE", help="offline: replay a capture's host stream")
    ap.add_argument("--password", default="", help="LDN passphrase as hex (live); default = "
                    "the built-in 64-byte emulator passphrase (shared by FRLG/RSE)")
    ap.add_argument("--phy", default="phy0", help="wifi phy for the LDN join (live)")
    ap.add_argument("--keys", default="~/.switch/prod.keys", help="Switch prod.keys (live)")
    ap.add_argument("--comm-id", help="LDN local_communication_id (hex) to join (live); "
                    "if omitted, joins the only available network (scan logs candidates)")
    ap.add_argument("--capture", metavar="FILE", help="(live) record EVERY Pia datagram both "
                    "directions to a .jsonl (incl. the SSID), so a live attempt can be "
                    "decrypted/analysed offline")
    args = ap.parse_args()
    if not 1 <= len(args.party) <= 6:
        ap.error(f"supply 1..6 party mons (gPlayerParty slots 0..5); got {len(args.party)}")
    # The host's Pia messages are zstd-compressed; without zstandard in THIS interpreter every
    # received message is unparseable and the sim silently never responds (tx stays 0). Fail loudly.
    if not cryptomod.HAVE_ZSTD:
        sys.exit(f"FATAL: 'zstandard' is not installed in this Python ({sys.executable}).\n"
                 f"The host's handshake is zstd-compressed - without it the sim can't read a single\n"
                 f"message and will never reply. Install it into THIS interpreter:\n"
                 f"    {sys.executable} -m pip install zstandard")

    lg = _Log(args.verbose)
    engine = run_live(args, lg) if args.live else run_replay(args, lg)

    saved = save_received(engine, args, lg)
    if not saved and args.live:
        print("\nTrade did not complete (no mon received).")
    # success: a mon was saved, or this was an offline replay (which exercises the path even if the
    # finite capture stops short of every configured trade).
    return 0 if (saved or args.replay) else 1


def save_received(engine, args, lg):
    """Save each received mon. trades==1 keeps the exact legacy single-file
    behavior (named by --out). trades>1 saves each as <stem>_trade<k>_<species>.pk3. Returns the
    number of mons saved."""
    mons = engine.received_mons or ([engine.received_mon] if engine.received_mon else [])
    if not mons:
        return 0
    ext = args.out_format
    if args.trades == 1:
        m = mons[0]
        saver = m.save_ek3 if ext == "ek3" else m.save_pk3
        saver(args.out, size=args.out_size)
        lg(f"\nReceived: {m.describe()}")
        lg.info(f"Received: {m.species_name} (#{m.species})")
        print(f"Saved -> {args.out} ({ext}, {args.out_size}B)")
        return 1
    stem, _ = os.path.splitext(args.out)
    lg(f"\nReceived {len(mons)} mon(s) over {args.trades} trade(s):")
    lg.info(f"Received {len(mons)} mon(s) over {args.trades} trade(s):")
    for k, m in enumerate(mons, start=1):
        sp = "".join(c for c in m.species_name if c.isalnum()) or f"sp{m.species}"
        path = f"{stem}_trade{k}_{sp}.{ext}"
        saver = m.save_ek3 if ext == "ek3" else m.save_pk3
        saver(path, size=args.out_size)
        lg(f"  trade {k}: {m.describe()}")
        lg.info(f"  trade {k}: {m.species_name} (#{m.species})")
        print(f"    saved -> {path} ({ext}, {args.out_size}B)")
    return len(mons)


if __name__ == "__main__":
    sys.exit(main())
