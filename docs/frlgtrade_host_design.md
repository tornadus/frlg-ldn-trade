# FRLG trade-host design

`frlgtrade_host.py` makes Linux the FireRed/LeafGreen Direct Corner leader. A single Switch joins
the Linux LDN network, Pia establishes the peer session, and Reliable carries an emulated parent
RFU link whose game-level endpoint is the leader-side trade state machine.

The implementation deliberately keeps the live-tested protocol bytes, message order, retry cadence,
VBlank timing, and disconnect grace period in the layer that owns them. The seams described here
are architectural boundaries, not extra buffering or protocol translation.

## Components and ownership

```mermaid
flowchart TD
    CLI[frlgtrade_host.py<br/>CLI and exit status] --> APP[HostApplication<br/>lifecycle and event loop]
    PROFILE[TrainerProfile<br/>human-readable identity] --> APP
    APP --> BEACON[host_beacon<br/>discovery records and beacon injector]
    APP --> LDN[HostTransport<br/>LDN AP and UDP :12345]
    APP --> PEER[HostPeerProtocol<br/>Pia Net / Session / RTT]
    PEER --> SESSION[HostSession<br/>stack composition]
    SESSION --> REL[Reliable<br/>ordering, ACKs, retransmission]
    SESSION --> RFU[RFULeader<br/>parent RFU framing and polling]
    SESSION --> TRADE[HostTradeEngine<br/>Direct Corner leader FSM]
    TRADE --> PK3[party .pk3/.ek3<br/>and received output]
```

- `TradeRunConfig` is immutable shared run configuration. It composes `TrainerProfile`, `TradePlan`,
  `LdnConfig`, and role-specific `HostOptions` or `JoinerOptions` rather than mixing unrelated
  settings in an argument namespace.
- `HostApplication` owns resource ordering: input validation, transport startup, beacon injection,
  the event loop, received-Pokémon persistence, interruption handling, and cleanup.
- `HostTransport` owns the LDN AP/network, virtual interfaces, participant events, and UDP sockets.
  It neither parses Pia nor advances the game state machine.
- `HostPeerProtocol` owns one Switch peer's Pia state: Net negotiation and property updates, Session
  acceptance, RTT, packet IDs, native/random nonce selection, encryption/framing, and Reliable
  message batching. It emits transport-independent `OutboundDatagram` values.
- `HostSession` composes Reliable, `RFULeader`, and `HostTradeEngine`. This is the boundary used by
  offline end-to-end tests; it has no socket or LDN dependency.
- `HostTradeEngine` owns the leader-side room entry, party/card exchange, selection and confirmation,
  animation/save barriers, menu cancellation, room exit, and close grace period. `HostTradeTiming`
  names the live-proven frame counts without changing them.
- `BeaconInjector` owns its raw monitor-interface socket and worker thread. `HostApplication` starts
  and stops it with the rest of the runtime resources.

## Data flow

```mermaid
flowchart LR
    SW[Switch] -->|802.11 association / LDN event| HT[HostTransport]
    SW -->|encrypted UDP 12345| HT
    HT -->|datagram + source IP| HP[HostPeerProtocol]
    HP -->|Reliable payload| HS[HostSession]
    HS -->|ordered RFU frame| RL[RFULeader]
    RL -->|child command row| TE[HostTradeEngine]
    TE -->|parent command row| RL
    RL -->|RFU frame| HS
    HS -->|Reliable emissions| HP
    HP -->|OutboundDatagram| HT
    HT -->|encrypted UDP 12345| SW
```

The application loop drains every datagram produced by `HostPeerProtocol` and sends it through
`HostTransport`. Timer deadlines come from the peer protocol, so Net/Session retries, RTT probes,
Reliable retransmission, and the approximately 59.727 Hz protocol tick do not depend on a fixed
polling delay.

## Startup and session establishment

```mermaid
sequenceDiagram
    participant C as CLI
    participant A as HostApplication
    participant T as HostTransport
    participant B as BeaconInjector
    participant P as HostPeerProtocol
    participant S as Switch

    C->>A: TradeRunConfig
    A->>T: start inactive Direct Corner network
    A->>B: start periodic Wi-Fi beacons
    S->>T: join LDN network
    T->>A: participant joined
    A->>P: on_participant_joined()
    P->>S: Pia Net connection request (retry until ACK)
    S-->>P: Net ACK and Session join request
    P->>S: Session update + unicast join response
    Note over P,S: optional diagnostic setting reverses this pair
    S-->>P: Session update ACK
    P->>S: RTT and Reliable/RFU traffic
    P->>T: active application-data property update
```

Malformed Pia, invalid padding, failed authentication, incomplete Reliable tiling, and mismatched
Session identities are logged and ignored. A Session request is accepted only when its constant ID,
Pia variables, source IP, and encrypted header agree with the current LDN peer.

## Trade and room-exit lifecycle

```mermaid
stateDiagram-v2
    [*] --> PlayerExchange
    PlayerExchange --> RoomEntry: LinkPlayer and trainer card
    RoomEntry --> PartyExchange: seat route and entry barriers
    PartyExchange --> Selection: party, mail, ribbons
    Selection --> Confirmation: Switch selects; leader offers configured slot
    Confirmation --> Animation: both confirm
    Animation --> Save: trade committed
    Save --> PartyExchange: another configured trade
    Save --> MenuExit: final party refresh
    MenuExit --> RoomExit: both cancel; five-second field wait
    RoomExit --> CloseGrace: Switch confirms room exit
    CloseGrace --> Disconnect: fifteen seconds of peer traffic
    Disconnect --> [*]
```

Room and menu transitions remain two-sided. After the final trade, Linux waits for the Switch trade
menu to become ready; the player selects **CANCEL** and confirms **YES**. The host then finishes the
native standby barriers, waits five seconds before leaving the room, and continues normal peer
traffic for fifteen seconds after the Switch confirms close. Only then is the RFU disconnect queued.
An LDN leave event stops peer output immediately.

## Shutdown and cleanup

```mermaid
sequenceDiagram
    participant S as Switch
    participant E as HostTradeEngine
    participant P as HostPeerProtocol
    participant A as HostApplication
    participant B as BeaconInjector
    participant T as HostTransport

    S->>E: READY_CLOSE_LINK confirmation
    E->>P: continue polls during 15-second grace
    E->>P: disconnect requested
    P->>S: final close poll, then RFU disconnect
    A->>A: save received Pokémon, if present
    A->>B: stop and join worker
    A->>T: close sockets/network and clean LDN vifs
```

The same cleanup runs on normal completion, `KeyboardInterrupt`, startup failure after partial
allocation, and beacon-worker failure. Captures are diagnostic output only and are closed during
cleanup; saving a received Pokémon is independent of capture logging.

## Trainer profile propagation

`frlgsim.config.DEFAULT_TRAINER` supplies the shared default identity. Both CLIs may derive an
immutable per-run `TrainerProfile` with `--ot`, `--version`, and decimal `--id TID[:SID]` overrides.
The profile validates Gen III names and numeric ranges, then derives every protocol view:

```mermaid
flowchart TD
    P[TrainerProfile<br/>name, TID, SID, gender,<br/>version, language, progress] --> D[LDN discovery<br/>name and public TID]
    P --> PS[Pia Session<br/>UTF-8 participant name]
    P --> LP[LinkPlayer<br/>SID:TID, version, language,<br/>gender and progress flags]
    LP --> TC[Trainer card<br/>Gen III name padded with FF]
```

TID and SID are combined as `SID << 16 | TID` for game records. Discovery exposes the public TID;
the Pia participant uses the readable name; LinkPlayer and trainer-card data use the Gen III
encoding. Host LinkPlayer/card names use `0xFF` padding, an intentional live-tested serialization
rule rather than profile configuration. Joiners retain native `0x00` padding; hosts use the
live-proven redundant `0xFF` padding.

## Failure handling

- Host preflight rejects radios without AP support before LDN creation and identifies the selected
  PHY/driver capability.
- Transport startup and beacon-thread failures abort the run and unwind already-created resources.
- Authentication/decryption and malformed-message failures do not enter the RFU/trade stack.
- Net and Session establishment retry at their proven cadence until acknowledged; RTT samples feed
  Reliable timing once the Session is finalized.
- An unexpected participant leave halts protocol output. After the normal room-close confirmation,
  the host retains the fifteen-second grace period even if the participant disappears, because the
  Switch may still be completing its fade, warp, and bridge teardown.
- Output is written only when a complete received Pokémon exists. Input `.pk3` and `.ek3` files are
  never treated as disposable runtime artifacts.

## Extending the host

Add protocol behavior at the lowest layer that understands it. Shared settings belong in
`TradeRunConfig` and its nested configuration values; OS/network behavior belongs in the application or transport; Pia messages belong
in `HostPeerProtocol`; RFU behavior belongs in `RFULeader`; and Direct Corner decisions belong in
`HostTradeEngine`. Keep encoders pure where possible and test each boundary using emitted datagrams,
Reliable payloads, RFU frames, or command rows. Do not duplicate trainer fields—derive new identity
representations from `TrainerProfile`.

The current implementation supports one joining Switch. Supporting more peers would require an
explicit `HostPeerProtocol` per participant, independent Pia variables/nonces/packet IDs, and a
game-level RFU policy; increasing the LDN participant limit alone is insufficient.

## Source map

| Source | Responsibility |
|---|---|
| `frlgtrade_host.py` | CLI parsing, configuration construction, application entry point |
| `frlgsim/host_app.py` | runtime lifecycle, event loop, output and cleanup |
| `frlgsim/config.py` | shared trainer, trade-plan, LDN, and role configuration |
| `frlgsim/trade_runtime.py` | shared CLI logging, party loading, slot parsing, and output saving |
| `frlgsim/host_beacon.py` | captured trade beacon, discovery mutation, raw beacon injection |
| `frlgsim/host_support.py` | OS-facing support such as sudo-aware key-path resolution |
| `frlgsim/transport.py` | LDN host lifecycle, interfaces, participant events, UDP data plane |
| `frlgsim/host_pia.py` | Pia framing and `HostPeerProtocol` |
| `frlgsim/host_session.py` | Reliable → RFU leader → trade composition |
| `frlgsim/reliable.py` | ordered/retransmitted application channel |
| `frlgsim/rfu_leader.py` | parent RFU framing, NI/UNI handshake, echo table |
| `frlgsim/host_trade.py` | leader trade-room state machine and timing |
| `frlgsim/linkplayer.py` | LinkPlayer and trainer-card encoders |
| `frlgsim/ldntrace.py` | optional JSONL diagnostics |
