"""Leader-side FRLG trade-room engine.

This module is deliberately below Pia/Reliable and above the parent RFU poller.  ``tick`` returns
one parent ``gSendCmd`` (seven u16 words) and ``feed_child_slot`` consumes the child's reflected
14-byte command row.  The host transport is responsible for putting the command in row 0 of a
70-byte parent UNI table and the latest child command in row 1.

The existing :mod:`frlgsim.trade` engine models the right-seat follower and therefore cannot simply
be run with ``mpid=0``: the leader owns SET_MONS/START/CONFIRM and all cancel decisions.  This engine
implements that complementary ownership while reusing the proven LinkPlayer, trainer-card, block,
party and RFU encoders.

With :class:`frlgsim.rfu_leader.RFULeader`, the live loop is intentionally small::

    event = rfu_leader.receive(unique_in_order_reliable_payload)
    if event == "uni":
        trade_leader.feed_child_slot(rfu_leader.child_cmd)
    parent_frame = rfu_leader.tick(trade_leader.tick())

``parent_frame`` is then queued as one Reliable GBA application payload.  When
``disconnect_requested`` is set, the loop first sends the queued close-link UNI poll, then queues
``rfu_leader.disconnect_frame()`` and calls ``mark_disconnect_sent``.
"""

from collections import deque
from dataclasses import dataclass

from . import block, linkplayer, mon as monmod, rfu, trade


H_LINK_PLAYER = "H_LINK_PLAYER"
H_ENTRY_CARD = "H_ENTRY_CARD"
H_ENTRY_SEAT = "H_ENTRY_SEAT"
H_PARTY = "H_PARTY"
H_SELECT = "H_SELECT"
H_CONFIRM = "H_CONFIRM"
H_ANIM = "H_ANIM"
H_SAVE = "H_SAVE"
H_LEAVE_MENU = "H_LEAVE_MENU"
H_CANCEL = "H_CANCEL"
H_RETURN_FIELD = "H_RETURN_FIELD"
H_EXIT = "H_EXIT"
H_CLOSE = "H_CLOSE"
H_DONE = "H_DONE"


@dataclass(frozen=True)
class HostTradeTiming:
    """Proven frame counts used by the leader-side trade state machine.

    Keeping these values together makes timing ownership explicit and lets tests accelerate the
    state machine without changing the live-tested defaults.
    """

    # The completed-trade capture has six consecutive child-initiated standby rounds (counts
    # 5..10) before BufferTradeParties starts again.
    save_barrier_rounds: int = 6
    # The child repeats the sixth post-save standby after 60 frames until the parent echo completes.
    save_final_standby_quiet_frames: int = 75
    # BufferTradeParties needs a quiescent window after the child's first IDLE reaches the host.
    party_link_settle_frames: int = 30
    startup_standby_echo_frames: int = 4
    # Longer than SendReadyExitStandbyUntilAllReady's native re-emission cadence.
    entry_final_standby_quiet_frames: int = 75
    # CB2_CreateTradeMenu needs time to finish installing its menu callback.
    final_menu_ready_frames: int = 5 * 60
    # Allow the field callback and room state to settle before emitting EXIT_ROOM.
    post_cancel_exit_wait_frames: int = 5 * 60
    # Keep Pia traffic alive after READY_CLOSE_LINK while the Switch completes its fade/warp.
    post_client_close_grace_frames: int = 15 * 60
    close_retry_frames: int = 60


DEFAULT_HOST_TRADE_TIMING = HostTradeTiming()

# Compatibility aliases for callers and tests that imported the original module constants.
SAVE_BARRIER_ROUNDS = DEFAULT_HOST_TRADE_TIMING.save_barrier_rounds
SAVE_FINAL_STANDBY_QUIET_FRAMES = DEFAULT_HOST_TRADE_TIMING.save_final_standby_quiet_frames
PARTY_LINK_SETTLE_FRAMES = DEFAULT_HOST_TRADE_TIMING.party_link_settle_frames
STARTUP_STANDBY_ECHO_FRAMES = DEFAULT_HOST_TRADE_TIMING.startup_standby_echo_frames
ENTRY_FINAL_STANDBY_QUIET_FRAMES = DEFAULT_HOST_TRADE_TIMING.entry_final_standby_quiet_frames
FINAL_MENU_READY_FRAMES = DEFAULT_HOST_TRADE_TIMING.final_menu_ready_frames
POST_CANCEL_EXIT_WAIT_FRAMES = DEFAULT_HOST_TRADE_TIMING.post_cancel_exit_wait_frames
POST_CLIENT_CLOSE_GRACE_FRAMES = DEFAULT_HOST_TRADE_TIMING.post_client_close_grace_frames
CLOSE_RETRY_FRAMES = DEFAULT_HOST_TRADE_TIMING.close_retry_frames
HOST_NAME_PAD = linkplayer.HOST_NAME_PAD

# Native Switch-leader route from the cable-club entrance to the LEFT trade chair.  Each tuple is
# (low-byte LINK_KEY_CODE, consecutive held-key frames).  The high byte is a monotonically rolling
# heldKeyCount generated below.  switch_complete_trade: counts 1..168, with READY exactly once at
# count 161; the child then completes standby rounds 2 and 3 before party exchange.
LINK_KEY_EMPTY = 0x11
LINK_KEY_UP = 0x13
LINK_KEY_LEFT = 0x14
LINK_KEY_READY = 0x16
LINK_KEY_EXIT_ROOM = 0x17
ENTRY_LEFT_CHAIR_ROUTE = (
    (LINK_KEY_EMPTY, 43),
    (LINK_KEY_UP, 9),
    (LINK_KEY_EMPTY, 4),
    (LINK_KEY_UP, 14),
    (LINK_KEY_EMPTY, 31),
    (LINK_KEY_LEFT, 5),
    (LINK_KEY_EMPTY, 12),
    (LINK_KEY_UP, 17),
    (LINK_KEY_EMPTY, 25),
    (LINK_KEY_READY, 1),
    (LINK_KEY_EMPTY, 7),
)


class HostTradeEngine:
    """Transport-independent, single-child FRLG trade leader.

    ``party`` is the host's 1..6 Pokémon party. ``offered_slots`` selects the host Pokémon offered
    each round.  A round begins only after the full LinkPlayer/card/seat entry and full party,
    mail, and ribbons exchange.  The leader waits for the child opcodes at every decision edge:

    READY -> SET_MONS -> INIT -> START -> READY_FINISH -> CONFIRM.

    Public integration contract:

    * call ``feed_child_slot(cmd14)`` for each *new* child UNI command;
    * call ``tick()`` once per VBlank and put its returned words in parent row 0;
    * echo the latest child command in parent row 1 (the RFU parent normally does this itself);
    * after ``disconnect_requested`` becomes true, queue emulator ``'D'`` only after Reliable has
      delivered the final close-link poll.
    """

    @property
    def close_confirmed(self):
        """Whether the child has confirmed it is leaving the trade room."""
        return self._close_confirmed

    def __init__(self, party, trade_slot=0, *, offered_slots=None, trades=1,
                 link_player=None, profile=None, anim_delay=1935, trust_pia=True, timing=None,
                 log=lambda *a: None):
        self.party = list(party)
        if not 1 <= len(self.party) <= 6:
            raise ValueError("party must contain 1..6 Pokémon")
        if not 1 <= trades <= 6:
            raise ValueError("trades must be 1..6")
        self.trades = trades
        self.offered_slots = trade.resolve_offered_slots(
            offered_slots, trade_slot, trades, party_size=len(self.party))
        if any(i >= len(self.party) for i in self.offered_slots):
            raise ValueError("offered slot exceeds party size")
        if link_player is not None and profile is not None:
            raise ValueError("supply link_player or profile, not both")
        self.lp = (profile.to_link_player() if profile is not None else link_player) \
            or linkplayer.LinkPlayer(name="EMU", version=linkplayer.VERSION_FIRE_RED)
        self.trainer_card = linkplayer.build_trainer_card(
            self.lp, mon_species=[m.species for m in self.party],
            name_pad=HOST_NAME_PAD)
        self.anim_delay = anim_delay
        self.trust_pia = trust_pia
        self.timing = timing if timing is not None else DEFAULT_HOST_TRADE_TIMING
        self.log = log
        self.info = getattr(log, "info", log)

        self.state = H_LINK_PLAYER
        self.state_history = [self.state]
        self.round = 0
        self.commits = 0
        self.received_mons = []
        self.child_link_player = None
        self.child_card = None
        self.child_party = bytearray(600)
        self.child_cursor = None
        self.done = False
        self.disconnect_requested = False

        self._rx = block.RecvBlock()
        self._words = deque()
        self._blocks = deque()
        self._sender = None
        self._expected = None
        self._party_pair = 0
        self._link_waiting_idle = False
        self._link_idle_frames = 0
        self._link_completed = None
        self._child_ready = False
        self._child_finish = False
        self._anim_wait = None
        self._save_rounds = 0
        self._save_last_count = None
        self._save_final_standby_seen = False
        self._save_standby_quiet = 0
        self._last_child_standby = None
        self._entry_final_standby_seen = False
        self._entry_standby_quiet = 0
        self._exit_count = 0
        self._cancel_standby_count = None
        self._return_standby_count = None
        self._return_standby_quiet = 0
        self._room_exit_wait = None
        self._child_exit_seen = False
        self._leave_menu_wait = None
        self._host_cancel_ready = False
        self._child_cancel_requested = False
        self._close_retry_wait = None
        self._close_confirmed = False
        self._close_grace_wait = None
        # SEND_HELD_KEYS carries a rolling high-byte counter and a low-byte overworld key. Entry is
        # an actual movement route, not a static READY flag; omitting it strands the child on the
        # black room-transition screen.
        self._held_count = 0
        self._held_plan = deque()
        self._held_steady = None
        self._held_label = None
        self.trace = []

        # The RFU leader announces IDs, then performs the session-one-shot LinkPlayer pull/exchange.
        self._queue_words(rfu.send_player_ids_words(), "SEND_PLAYER_IDS")
        self._request_and_send(trade.BLOCK_REQ_SIZE_NONE,
                               linkplayer.build_block(
                                   self.lp, name_pad=HOST_NAME_PAD).ljust(200, b"\x00"),
                               "link_player")

    def _set_state(self, state):
        if state != self.state:
            self.state = state
            self.state_history.append(state)
            self.trace.append(("state", state))
            self.log(f"host trade: -> {state}")

    def _queue_words(self, words, label):
        self._words.append(list(words))
        self.trace.append(("queue", label))

    def _queue_block(self, data, label):
        self._blocks.append((bytes(data), label))
        self.trace.append(("queue_block", label, len(data)))

    def _set_held_plan(self, runs, label, steady=None):
        self._held_plan.clear()
        for keycode, count in runs:
            self._held_plan.extend([keycode & 0xFF] * max(0, int(count)))
        self._held_steady = None if steady is None else steady & 0xFF
        self._held_label = label
        self.trace.append(("held_plan", label, len(self._held_plan), self._held_steady))

    def _hold_key(self, keycode, label):
        """Emit a state-changing key once, then EMPTY keepalives until the peer advances."""
        self._set_held_plan(((keycode, 1),), label, steady=LINK_KEY_EMPTY)

    def _start_entry_route(self):
        self._set_held_plan(ENTRY_LEFT_CHAIR_ROUTE, "ENTRY_LEFT_CHAIR")

    def _release_key(self, label):
        if self._held_plan or self._held_steady is not None:
            self.trace.append(("release", label))
        self._held_plan.clear()
        self._held_steady = None
        self._held_label = None

    def _next_held_words(self):
        if self._held_plan:
            keycode = self._held_plan.popleft()
        elif self._held_steady is not None:
            keycode = self._held_steady
        else:
            return None
        self._held_count = (self._held_count + 1) & 0xFF
        value = (self._held_count << 8) | keycode
        self.trace.append(("emit_held", self._held_label, value))
        words = rfu.held_keys_words(value)
        # If the Switch exited first, still expose our EXIT_ROOM for one complete parent poll before
        # advancing to READY_CLOSE_LINK. This mirrors both players' room-exit decisions on the wire.
        if (keycode == LINK_KEY_EXIT_ROOM and self.state == H_EXIT
                and self._child_exit_seen):
            self._complete_room_exit()
        return words

    def _request_and_send(self, reqtype, data, expected):
        self._expected = expected
        self._queue_words(rfu.send_block_req_words(reqtype), f"BLOCK_REQ:{reqtype}:{expected}")
        self._queue_block(data, f"host:{expected}")

    def _send_linkcmd(self, cmd, cursor=0):
        self._queue_block(trade.linkcmd_block(cmd, cursor), trade.LINKCMD_NAMES[cmd])

    def _enter_cancel_to_leave(self):
        """Resolve the native leader decision after both players selected CANCEL."""
        if not (self._host_cancel_ready and self._child_cancel_requested):
            raise RuntimeError("BOTH_CANCEL requires both leader and follower cancel decisions")
        self._set_state(H_CANCEL)
        self._cancel_standby_count = None
        self._return_standby_count = None
        self._return_standby_quiet = 0
        self._room_exit_wait = None
        self._child_exit_seen = False
        self._send_linkcmd(trade.BOTH_CANCEL_TRADE)
        self.info("Switch CANCEL received; both players cancelled. Leaving the trade menu.")

    def _leader_cancel_is_ready(self):
        """Latch the emulated leader's local CANCEL choice after the menu-settle delay."""
        self._host_cancel_ready = True
        self.trace.append(("leader_cancel_ready",))
        if self._child_cancel_requested:
            self._enter_cancel_to_leave()
        else:
            self.info(
                "Linux host is ready to leave. On the Switch, select CANCEL and confirm YES.")

    def _finish_party_exchange(self):
        self._expected = None
        if self.round >= self.trades:
            self._set_state(H_LEAVE_MENU)
            self._leave_menu_wait = self.timing.final_menu_ready_frames
            self._host_cancel_ready = False
            self._child_cancel_requested = False
            self.info("Final party refresh complete; waiting 5 seconds for the trade menu.")
        else:
            self._set_state(H_SELECT)

    def _begin_room_exit(self, *, child_already_exited=False):
        self._set_state(H_EXIT)
        self._room_exit_wait = None
        self._child_exit_seen = bool(child_already_exited)
        self._hold_key(LINK_KEY_EXIT_ROOM, "EXIT_ROOM_KEY")
        if child_already_exited:
            self.info("Switch exited the room first; sending the Linux EXIT_ROOM response.")
        else:
            self.info("Five-second room delay complete; Linux is exiting the trade room.")

    def _complete_room_exit(self):
        """Both room-exit decisions are visible; begin the RFU close handshake."""
        if self.state != H_EXIT:
            return
        self._release_key("EXIT_ROOM_KEY")
        self.trace.append(("child_key", "EXIT_ROOM"))
        self._set_state(H_CLOSE)
        self._close_confirmed = False
        self._close_grace_wait = None
        for _ in range(self.timing.startup_standby_echo_frames):
            self._queue_words(rfu.close_link_words(self._exit_count), "READY_CLOSE_LINK")
        self._close_retry_wait = self.timing.close_retry_frames
        self.info("Both players left the room; closing the RFU link.")

    def _begin_card_exchange(self):
        self._set_state(H_ENTRY_CARD)
        self._request_and_send(trade.BLOCK_REQ_SIZE_100, self.trainer_card, "card")

    def _begin_party_exchange(self):
        self._set_state(H_PARTY)
        self.child_party = bytearray(600)
        self._party_pair = 0
        self._request_party_pair()

    def _request_party_pair(self):
        host_party = monmod.party_blocks(monmod.build_player_party(self.party))
        self._request_and_send(trade.BLOCK_REQ_SIZE_200,
                               host_party[self._party_pair], f"party:{self._party_pair}")

    def _after_child_block(self, count, data):
        expected = self._expected
        self.trace.append(("child_block", expected, count))
        expected_count = {
            "link_player": trade.COUNT_PARTY,
            "card": trade.COUNT_TRAINER_CARD,
            "mail": trade.COUNT_MAIL,
            "ribbons": trade.COUNT_RIBBON,
        }.get(expected, trade.COUNT_PARTY if expected and expected.startswith("party:") else None)
        if expected_count is None:
            self.trace.append(("unexpected_child_block", count))
            return
        if count != expected_count:
            raise ValueError(f"child block count {count}, expected {expected_count} for {expected}")
        if expected == "link_player":
            lp, ok = linkplayer.parse_block(data)
            if not ok:
                raise ValueError("child LinkPlayer block has invalid GameFreak magic")
            self.child_link_player = lp
            self._expected = "warp0"
            return
        if expected == "card":
            self.child_card = bytes(data[:100])
            self._expected = "warp1"
            return
        if expected and expected.startswith("party:"):
            i = int(expected.split(":", 1)[1])
            self.child_party[i * 200:(i + 1) * 200] = data[:200]
            # BufferTradeParties gates the next request on IsLinkTaskFinished(), not a standby
            # barrier. On the wire, wait until the child has stopped retransmitting SEND_BLOCK and
            # produced a sustained run of IDLE polls before advancing to the next pair.
            self._link_waiting_idle = True
            self._link_idle_frames = 0
            self._link_completed = f"party:{i}"
            self.trace.append(("party_wait_idle", i))
            self.info(f"Party block {i + 1}/3 exchanged; waiting for the Switch link task to finish.")
            return
        if expected == "mail":
            self._link_waiting_idle = True
            self._link_idle_frames = 0
            self._link_completed = "mail"
            self.trace.append(("mail_wait_idle",))
            self.info("Mail block exchanged; waiting for the Switch link task to finish.")
            return
        if expected == "ribbons":
            self._link_waiting_idle = True
            self._link_idle_frames = 0
            self._link_completed = "ribbons"
            self.trace.append(("ribbons_wait_idle",))
            self.info("Ribbon block exchanged; waiting for the Switch link task to finish.")

    def feed_child_slot(self, slot):
        """Consume one child gSendCmd row (14 bytes, rolling tag permitted)."""
        if bytes(slot) == rfu.idle_slot():
            if self.state == H_SAVE and self._save_final_standby_seen:
                self._save_standby_quiet += 1
                if (self._save_standby_quiet
                        >= self.timing.save_final_standby_quiet_frames):
                    self.trace.append(("save_final_standby_complete",
                                       self._save_last_count))
                    self._begin_party_exchange()
                return
            if self.state == H_ENTRY_SEAT and self._entry_final_standby_seen:
                self._entry_standby_quiet += 1
                if (self._entry_standby_quiet
                        >= self.timing.entry_final_standby_quiet_frames):
                    self.trace.append(("entry_final_standby_complete",
                                       self._entry_standby_quiet))
                    self._expected = None
                    self._begin_party_exchange()
                return
            if self.state == H_PARTY and self._link_waiting_idle:
                self._link_idle_frames += 1
                if self._link_idle_frames >= self.timing.party_link_settle_frames:
                    completed = self._link_completed
                    self._link_waiting_idle = False
                    self._link_completed = None
                    if completed and completed.startswith("party:"):
                        i = int(completed.split(":", 1)[1])
                    else:
                        i = None
                    if i is not None and i < 2:
                        self._party_pair = i + 1
                        self.trace.append(("party_link_finished", i))
                        self._request_party_pair()
                    elif i == 2:
                        self.info("Party blocks 3/3 exchanged; exchanging mail and ribbon data.")
                        self._request_and_send(
                            trade.BLOCK_REQ_SIZE_220, b"\x00" * 220, "mail")
                    elif completed == "mail":
                        self._request_and_send(
                            trade.BLOCK_REQ_SIZE_40, b"\x00" * 40, "ribbons")
                    elif completed == "ribbons":
                        self._finish_party_exchange()
            return
        if self.state == H_PARTY and self._link_waiting_idle:
            self._link_idle_frames = 0
        rec = rfu.parse_slot(slot)
        if rec is None:
            return
        op = rec["op"]
        if op == rfu.SEND_BLOCK_INIT:
            self._rx.on_init(rec["count"], rec.get("owner_raw"))
            return
        if op == rfu.SEND_BLOCK:
            was_done = self._rx.done
            self._rx.on_block(rec["index"], rec["frag"])
            if self._rx.done and not was_done:
                data, count = self._rx.data(), self._rx.count
                self._rx.consume()
                self._on_child_block(count, data)
            return
        if op == rfu.SEND_HELD_KEYS:
            key = rec.get("keycode", 0) & 0xFF
            if key == LINK_KEY_READY and self.state == H_ENTRY_SEAT:
                self._child_ready = True
                self.trace.append(("child_key", "READY"))
                self._maybe_finish_entry()
            elif key == LINK_KEY_EXIT_ROOM and self.state == H_RETURN_FIELD:
                # The Switch is allowed to walk out during our five-second delay. Send our own
                # EXIT_ROOM once, then close exactly as if Linux had initiated.
                self.trace.append(("child_exit_first",))
                self._begin_room_exit(child_already_exited=True)
            elif key == LINK_KEY_EXIT_ROOM and self.state == H_EXIT:
                self._child_exit_seen = True
                self._complete_room_exit()
            return
        if op == rfu.READY_EXIT_STANDBY:
            self._on_child_standby(rec.get("count", 0))
        elif op == rfu.READY_CLOSE_LINK and self.state == H_CLOSE:
            self.trace.append(("child_close_ready", rec.get("count", 0)))
            if not self._close_confirmed:
                self._close_confirmed = True
                self._close_grace_wait = self.timing.post_client_close_grace_frames
                self.trace.append(("child_close_confirmed",
                                   rec.get("count", 0),
                                   self.timing.post_client_close_grace_frames))
                self.info(
                    "Switch confirmed it left the trade room; keeping peer traffic active "
                    "for 15 seconds before disconnecting.")

    def _on_child_block(self, count, data):
        if count == trade.COUNT_LINKCMD:
            self._on_child_linkcmd(int.from_bytes(data[:2], "little"),
                                   int.from_bytes(data[2:4], "little"))
        else:
            self._after_child_block(count, data)

    def _on_child_standby(self, count):
        if self.state == H_PARTY:
            # Late room-entry standby traffic can overlap BufferTradeParties, but it is not the
            # protocol gate for the next block request.
            self._link_idle_frames = 0
            return
        # Keep startup barrier echoes visible across several child polls.  One 7.5.4 live run
        # repeated child count 0 forever after the parent exposed count 0 for only one VBlank and
        # replaced it immediately with the card request; 7.5.2 happened to catch the same one-frame
        # pulse. Native gSendCmd remains current until the next link task overwrites it, so model a
        # short persistent pulse before queueing the next startup operation. Save/cancel barriers
        # keep their single echo because they are already multi-round handshakes.
        repeats = (self.timing.startup_standby_echo_frames
                   if self.state in (H_LINK_PLAYER, H_ENTRY_CARD, H_ENTRY_SEAT,
                                     H_CANCEL, H_RETURN_FIELD) else 1)
        for _ in range(repeats):
            self._queue_words(rfu.exit_standby_words(count), f"STANDBY:{count}")
        self._last_child_standby = count
        self._exit_count = max(self._exit_count, count + 1)
        if self.state == H_LINK_PLAYER and self._expected == "warp0":
            self._begin_card_exchange()
        elif self.state == H_ENTRY_CARD and self._expected == "warp1":
            self._set_state(H_ENTRY_SEAT)
            self._expected = "warp2"
            self._start_entry_route()
        elif self.state == H_ENTRY_SEAT:
            if count >= 3:
                self._entry_standby_quiet = 0
            self._maybe_finish_entry()
        elif self.state == H_SAVE:
            if self._save_last_count is None:
                self._save_last_count = count
                self._save_rounds = 1
            elif count == self._save_last_count:
                pass  # duplicate reflection of the same barrier round
            elif count == ((self._save_last_count + 1) & 0xFFFF):
                self._save_last_count = count
                self._save_rounds += 1
            else:
                self.trace.append(("save_standby_out_of_sequence",
                                   self._save_last_count, count))
            if self._save_rounds >= self.timing.save_barrier_rounds:
                self._save_standby_quiet = 0
                if not self._save_final_standby_seen:
                    self._save_final_standby_seen = True
                    self.trace.append(("save_final_standby_seen", count))
                    self.info(
                        "Save barriers complete; waiting for the Switch menu handoff to finish.")
        elif self.state == H_CANCEL:
            if self._cancel_standby_count is None:
                self._cancel_standby_count = count
            elif count == ((self._cancel_standby_count + 1) & 0xFFFF):
                # The next child-initiated count is wire proof that the cancel barrier passed.
                self._set_state(H_RETURN_FIELD)
                self._return_standby_count = count
                self._room_exit_wait = self.timing.post_cancel_exit_wait_frames
                self.trace.append(("cancel_standby_complete",
                                   self._cancel_standby_count, count))
                self.info("Trade menu closed; waiting 5 seconds before Linux exits the room.")
        elif self.state == H_RETURN_FIELD:
            self._return_standby_count = count

    def _maybe_finish_entry(self):
        """Latch the final post-seat barrier; open the menu only after its native resend goes quiet."""
        if (self.state == H_ENTRY_SEAT and self._last_child_standby is not None
                and self._last_child_standby >= 3):
            self._release_key("ENTRY_LEFT_CHAIR")
            self._entry_final_standby_seen = True
            self._entry_standby_quiet = 0
            self.trace.append(("entry_final_standby_seen", self._last_child_standby))

    def _on_child_linkcmd(self, cmd, cursor):
        self.trace.append(("child_linkcmd", trade.LINKCMD_NAMES.get(cmd, hex(cmd)), cursor))
        if cmd == trade.READY_TO_TRADE and self.state == H_SELECT:
            self.child_cursor = cursor % 6
            self._set_state(H_CONFIRM)
            self._send_linkcmd(trade.SET_MONS_TO_TRADE, self.offered_slots[self.round])
        elif cmd == trade.INIT_BLOCK and self.state == H_CONFIRM:
            self._set_state(H_ANIM)
            self._anim_wait = self.anim_delay
            self._send_linkcmd(trade.START_TRADE)
        elif cmd == trade.READY_FINISH_TRADE and self.state == H_ANIM:
            self._child_finish = True
        elif cmd == trade.REQUEST_CANCEL and self.state == H_LEAVE_MENU:
            # Leader_HandleCommunication reaches BOTH_CANCEL only when both playerSelectStatus
            # values are CANCEL. A follower REQUEST_CANCEL is therefore a prerequisite, not merely
            # an acknowledgement of an unsolicited leader verdict.
            self._child_cancel_requested = True
            self.trace.append(("child_cancel_requested",))
            if self._host_cancel_ready:
                self._enter_cancel_to_leave()
            else:
                self.info("Switch requested CANCEL; honoring it after the 5-second menu wait.")
        elif cmd in (trade.READY_TO_TRADE, trade.READY_CANCEL_TRADE) \
                and self.state == H_LEAVE_MENU:
            # Native Leader_HandleCommunication sends PLAYER_CANCEL when the leader selected
            # CANCEL but the follower selected/confirmed a Pokemon. This returns the follower to
            # its menu rather than falsely beginning another configured trade.
            self._send_linkcmd(trade.PLAYER_CANCEL_TRADE)
            self.trace.append(("reject_extra_trade", trade.LINKCMD_NAMES.get(cmd, hex(cmd))))
            self.info(
                "Switch selected another trade; Linux declined it. Dismiss the message, then "
                "select CANCEL and confirm YES to leave.")

    def _commit(self):
        host_slot = self.offered_slots[self.round]
        child_slot = self.child_cursor
        if child_slot is None:
            raise RuntimeError("cannot commit without child selection")
        off = child_slot * monmod.PARTY_MON_SIZE
        received = monmod.Mon(bytes(self.child_party[off:off + monmod.PARTY_MON_SIZE]))
        self.received_mons.append(received)
        self.party[host_slot] = received
        self.round += 1
        self.commits += 1
        self.trace.append(("commit", self.commits, host_slot, child_slot))
        self._send_linkcmd(trade.CONFIRM_FINISH_TRADE)
        self._set_state(H_SAVE)
        self._save_rounds = 0
        self._save_last_count = None
        self._save_final_standby_seen = False
        self._save_standby_quiet = 0
        self._child_finish = False
        self._anim_wait = None

    def tick(self):
        """Advance one VBlank and return the parent's seven-word gSendCmd."""
        if self.state == H_LEAVE_MENU and self._leave_menu_wait is not None:
            self._leave_menu_wait -= 1
            if self._leave_menu_wait <= 0:
                self._leave_menu_wait = None
                self._leader_cancel_is_ready()

        if self.state == H_RETURN_FIELD and self._room_exit_wait is not None:
            self._room_exit_wait -= 1
            if self._room_exit_wait <= 0:
                self._begin_room_exit()

        if self.state == H_CLOSE and not self.disconnect_requested:
            if self._close_grace_wait is not None:
                self._close_grace_wait -= 1
                if self._close_grace_wait <= 0:
                    self._close_grace_wait = None
                    self.disconnect_requested = True
                    self.trace.append(("close_grace_complete",))
                    self.info(
                        "Fifteen-second room-exit buffer complete; closing the RFU session.")
            self._close_retry_wait -= 1
            if self._close_retry_wait <= 0:
                for _ in range(self.timing.startup_standby_echo_frames):
                    self._queue_words(rfu.close_link_words(self._exit_count), "READY_CLOSE_LINK")
                self._close_retry_wait = self.timing.close_retry_frames

        if self.state == H_ANIM and self._anim_wait is not None:
            if self._anim_wait > 0:
                self._anim_wait -= 1
            elif self._child_finish:
                self._commit()

        if self._words:
            return self._words.popleft()
        held_words = self._next_held_words()
        if held_words is not None:
            return held_words
        if self._sender is None and self._blocks:
            data, label = self._blocks.popleft()
            self._sender = block.BlockSender(data, owner=0, trust_pia=self.trust_pia)
            self.trace.append(("send_block", label, len(data)))
        if self._sender is not None:
            words = self._sender.tick(None)
            if self._sender.done:
                self._sender = None
            return words
        return [0] * 7

    @property
    def established(self):
        return self.child_link_player is not None

    def mark_disconnect_sent(self):
        """Notify the FSM that the RFU adapter queued/delivered emulator ``'D'``.

        The adapter owns that frame because it captured the child's connect id.  Keeping this as an
        explicit acknowledgement prevents the trade engine from declaring success before the final
        close-link poll and disconnect have entered Reliable's send window.
        """
        if not self.disconnect_requested:
            raise RuntimeError("disconnect sent before close-link handshake")
        self.done = True
        self._set_state(H_DONE)
