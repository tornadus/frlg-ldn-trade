"""FireRed/LeafGreen trade protocol models for both LDN joiner and host roles.

The original stack joins a real console as the wireless RFU child.  The host stack composes
``HostPeerProtocol`` (Pia), ``HostSession`` (Reliable/RFU), and ``HostTradeEngine`` (game state) to
act as the leader.  Both roles share the byte-level Pokémon, block, and framing models.

Layer stack (bottom-up), one per-VBlank RFU command slot becomes:
    14-byte RFU slot (rfu.py)
      -> emulator 0x54 frame (gbaframe.py)
        -> Reliable(10) + Pia message (reliable.py)
          -> zstd (optional) + Pia AES-GCM (crypto.py)
            -> UDP :12345 (transport.py)

The trade payloads are PKHeX-compatible .pk3 files (mon.py): the on-wire 100-byte party
`struct Pokemon` (encrypted + shuffled) IS the canonical .pk3 layout.

The overworld/seat phase (before the trade engine has block work) is driven by linkstate.py: a
held-keys (0xBE00) keepalive FSM that sits the joiner at the RIGHT seat (mpId 1) and exits via a
graceful cancel-to-leave, mirroring CB1_UpdateLinkState [src/overworld.c].

The host's standby / close-link barriers (READY_EXIT_STANDBY 0x6600 / READY_CLOSE_LINK 0x5F00) are
answered by barrier.py: a reactive responder inside the trade engine that mirrors the host's
broadcast round count so the host's IsLinkTaskFinished gate clears, mirroring the child branch of
Rfu_LinkStandby / SendReadyCloseLink [src/link_rfu_2.c:1471-1602].

The union-room -> trade-center ENTRY (the phase BEFORE S1) is modeled by trade.EntryPhase + a
REQ-driven 100B trainer-card supplier (linkplayer.build_trainer_card): P0/P3 standby windows answered
by barrier.py, P1 trainer-card pull (BLOCK_REQ_SIZE_100, count=9) supplied by the engine, P2 seat
held-keys READY by linkstate.py, P4/P5 handoff into the trade FSM. It is one-shot per session (never
re-fires on trades 2..6) [src/union_room.c:1753-1933; src/cable_club.c:827-942].
"""

__all__ = [
    "barrier", "charmap", "config", "crypto", "gbaframe", "host_app", "host_beacon",
    "host_pia", "host_session", "host_support", "host_trade", "linkstate", "mon",
    "reliable", "rfu", "rfu_leader", "trade_runtime",
]
