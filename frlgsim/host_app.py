"""Application runtime for hosting one complete FRLG trade session.

``HostApplication`` owns OS resources and scheduling.  Protocol bytes and peer
state live in :mod:`frlgsim.host_pia`; Reliable/RFU/trade state lives in
:class:`frlgsim.host_session.HostSession`.
"""

import os
import time

from . import config as configmod, host_session, host_trade, ldntrace, trade_runtime, transport
from .linkplayer import HOST_NAME_PAD
from .host_beacon import BeaconInjector, build_trade_app_data
from .host_pia import HostPeerProtocol
from .host_support import resolve_keys


HOST_CONTROL_POLL_SECONDS = 0.05


class HostApplication:
    """Wire together the host components and own their deterministic cleanup."""

    def __init__(self, config, *, log=print,
                 transport_factory=transport.HostTransport,
                 injector_factory=BeaconInjector):
        if not isinstance(config.role, configmod.HostOptions):
            raise ValueError("HostApplication requires HostOptions")
        self.config = config
        self.profile = config.profile
        self.plan = config.plan
        self.ldn = config.ldn
        self.options = config.role
        self.log = log
        self.info = getattr(log, "info", log)
        self.transport_factory = transport_factory
        self.injector_factory = injector_factory
        self.network = None
        self.injector = None
        self.tracer = None
        self.session = None
        self.peer = None
        self._saved_commits = 0
        self._last_trade_state = None
        self._absence_logged = False

    def _load_party(self):
        party = trade_runtime.load_party(self.plan.party_paths, self.log)
        self.info(f"Loaded {len(party)} party Pokémon "
                  f"(planned offered slots: {self.plan.offered_slots}).")
        return party

    def _resolve_phy_and_keys(self):
        phy = self.ldn.phy
        if phy == "auto":
            phy = transport.find_ap_phy(log=self.log)
            if phy is None:
                raise SystemExit("no AP-capable phy found; present phys: "
                                 f"{', '.join(transport.list_phys()) or 'none'}")
        keys = resolve_keys(self.ldn.keys_path)
        if not os.path.exists(keys):
            raise SystemExit(f"prod.keys not found at {keys!r}; pass --keys with an absolute path")
        return phy, keys

    def _build_components(self):
        party = self._load_party()
        phy, keys = self._resolve_phy_and_keys()
        link_player = self.profile.to_link_player()
        self.session = host_session.HostSession(
            party, plan=self.plan, profile=self.profile, log=self.log)
        inactive, active = build_trade_app_data(
            self.profile, self.session.rfu.host_session_id)
        self.tracer = (ldntrace.Tracer(self.ldn.capture_path, log=self.log)
                       if self.ldn.capture_path else None)
        self.network = self.transport_factory(
            app_data=inactive, password=self.ldn.password,
            nickname=self.profile.discovery_name, keys_path=keys,
            local_comm_id=self.ldn.local_comm_id,
            scene_id=self.options.scene_id,
            max_participants=self.options.max_participants,
            phyname=phy, channel=self.options.channel,
            skip_encryption=self.options.skip_encryption,
            tracer=self.tracer, log=self.log)
        self.peer = HostPeerProtocol(
            self.network, self.profile, self.session, active,
            native_nonce_sequence=self.options.native_nonce_sequence,
            session_response_first=self.options.session_response_first,
            log=self.log)
        self._last_trade_state = self.session.trade.state
        return link_player

    def _log_identity(self, link_player):
        wire = link_player.pack(name_pad=HOST_NAME_PAD)
        self.info(f"Host identity: OT={self.profile.name!r}, "
                  f"TID=0x{self.profile.tid:04x}, SID=0x{self.profile.sid:04x}")
        self.info("Host LinkPlayer display identity: "
                  f"name_bytes={wire[8:16].hex()} "
                  f"language={int.from_bytes(wire[26:28], 'little')}")
        self.info(f"RFU parent identity: raw={self.session.rfu.host_session_id.hex()} "
                  f"u16=0x{int.from_bytes(self.session.rfu.host_session_id, 'little'):04x} "
                  "(shared by discovery beacon and A response)")
        self.info("RFU block delivery: " + (
            "Pia-backed send-once mode (recommended for this LDN bridge)."
            if self.plan.trust_pia else
            "raw-RFU retransmit mode (diagnostic; may flood the Pia bridge)."))
        self.info("Pia nonce mode: " + (
            "native session-wide counter" if self.options.native_nonce_sequence
            else "independent random values"))

    def _send_pending(self, datagrams):
        for outbound in datagrams:
            self.network.send(outbound.data, outbound.destination)

    def _log_protocol_events(self, events):
        if "connect" in events:
            self.info("Switch requested the RFU link; preparing the leader A response.")
        if "child_ni_complete" in events:
            self.info("Received the Switch RFU identity; sending join-status NI.")

    def _log_trade_progress(self):
        state = self.session.trade.state
        if state != self._last_trade_state:
            self._last_trade_state = state
            message = {
                host_trade.H_ENTRY_CARD: "LinkPlayer exchange complete; exchanging trainer cards.",
                host_trade.H_ENTRY_SEAT: "Trainer cards exchanged; walking the Linux leader into the left chair.",
                host_trade.H_PARTY: "Trade-room entry complete; exchanging party data.",
                host_trade.H_SELECT: "Party exchange complete; trade selection is active.",
            }.get(state)
            if message:
                self.info(message)
        if self.session.trade.commits > self._saved_commits:
            self._saved_commits = self.session.trade.commits
            self._save_received()

    def _save_received(self):
        mons = self.session.trade.received_mons
        trade_runtime.save_received_mons(
            mons, output_path=self.plan.output_path,
            output_size=self.plan.output_size,
            output_format=self.plan.output_format,
            trades=self.plan.trades, log=self.log)

    def run(self):
        joined_once = False
        rfu_ni_logged = False
        try:
            link_player = self._build_components()
            self._log_identity(link_player)
            self.network.start(preflight=not self.options.skip_preflight)
            self.injector = self.injector_factory(
                channel=self.options.channel, log=self.log)
            self.injector.start()
            self.info("Hosting Direct Corner. On the Switch choose Join Group.")
            while True:
                if self.injector.error is not None:
                    raise RuntimeError(f"802.11 beacon injector stopped: {self.injector.error}")
                if self.network.participants and not joined_once:
                    joined_once = True
                    self.peer.on_participant_joined()
                    self.info("Switch joined the Linux LDN host successfully.")
                if joined_once and not self.network.participants:
                    if self.session.trade.close_confirmed and not self.session.trade.done:
                        if not self._absence_logged:
                            self._absence_logged = True
                            self.info("The console left LDN after confirming room exit; "
                                      "finishing the 15-second host grace period.")
                    else:
                        self.session.on_ldn_leave()
                        self.info("The console left the LDN network; stopping host peer traffic.")
                        break

                for datagram, src_ip in self.network.recv():
                    events = self.peer.receive(datagram, src_ip)
                    self._log_protocol_events(events)
                    self._send_pending(self.peer.drain())

                now = time.monotonic()
                self._send_pending(self.peer.tick(now))
                self._log_trade_progress()
                if self.session.rfu.ni_complete and not rfu_ni_logged:
                    rfu_ni_logged = True
                    self.info("RFU NI handshake complete; parent UNI and trade-room startup are active.")
                if self.session.trade.done and not self.network.participants:
                    self.info("Room-exit grace period complete; host peer traffic stopped cleanly.")
                    break
                timeout = self.peer.next_deadline(now, HOST_CONTROL_POLL_SECONDS)
                self.network.wait_readable(timeout)
        except KeyboardInterrupt:
            self.log("[host] interrupted; shutting down")
        finally:
            if self.injector is not None:
                self.injector.stop()
            if self.network is not None:
                self.network.stop()
            if self.tracer is not None:
                self.tracer.close()
                self.log(f"[host] trace written: {self.ldn.capture_path} "
                         f"(counts: {self.tracer.counts})")
        return joined_once
