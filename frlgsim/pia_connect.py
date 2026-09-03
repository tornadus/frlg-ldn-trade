"""Pia connection layer (S0) - Net + Session(new) + RTT, the handshake the host must complete
before it registers the sim as a peer (no "OK" prompt until then).

Decoded from the kinnay NintendoClients wiki (Pia 6.32+ numbering: 1=Net, 3=RTT, 10=Reliable,
13=Session-new) and the reference capture. KEY FACTS:
  * The 2-byte station "variable id" is ASSIGNED per session, NOT derived from the MAC. Each
    side LEARNS the other's from the packet header: Pia header is [dst_var(2)][src_var(2)], and
    the message footer is the DESTINATION var id. So the sim reads its own var id (= IN header
    dst) and the host's (= IN header src) off the first incoming packet.
  * The 8-byte "constant id" = the station's 6-byte MAC + 0x0000 (from the LDN participant list).
  * Net (proto 1): header [ver=1][type][size:u16 BE]; type 0x11 = connection request (host->us),
    0x12 = our response. Session (proto 13): join request (type 0) below. RTT (proto 3): type 0
    request -> type 1 response.

Verified: build_session_join() reproduces the reference capture's message #3 byte-for-byte
(except the random nonce). The Session join's exact PlayerInfo/version constants are templated
from the reference capture and may need live tuning against the real host.
"""

# Proto ids (Pia 6.32+)
PROTO_NET = 1
PROTO_RTT = 3
PROTO_RELIABLE = 10
PROTO_SESSION = 13

# The reserved session pseudo-station var-id. RTT (proto 3) + session-control ride header dst=0x0001
# (NOT the peer var); the footer recipient stays the host var. (observed: RTT dst=0x0001 both ways)
SESSION_VAR = 0x0001
RTT_ORIGINATE_PERIOD = 10    # VBlanks between guest-originated RTT requests (~6/s; reference capture ~5.9/s)

# Net message types
NET_CONN_REQUEST = 0x11      # host -> joiner
NET_CONN_RESPONSE = 0x12     # joiner -> host
NET_UPDATE_PROPERTY = 0x50   # host -> joiner (mid-session "update network property", retransmit-until-acked)
NET_UPDATE_PROPERTY_ACK = 0x51   # joiner -> host

# Session(new) message types
SESSION_JOIN_REQUEST = 0
SESSION_JOIN_RESPONSE = 2
SESSION_UPDATE = 5
SESSION_UPDATE_ACK = 6
SESSION_LEFT_SYNC = 7

# Session join templated constants (from the reference capture's message #3 - confirm/tune live).
DEFAULT_PROTOCOLS = [(1, 0), (3, 5), (5, 1), (10, 3), (13, 7), (15, 0)]
DEFAULT_APP_VER = bytes.fromhex("0058")
DEFAULT_PLAYER_ID = bytes.fromhex("00000000000000010000000000000000")


def _ip4(ip):
    return bytes(int(x) for x in ip.split("."))


# --- Net protocol (proto 1) -----------------------------------------------------------------
def parse_net(payload):
    """-> (version, type, body) for a Net message (header = [ver][type][size:u16 BE])."""
    if len(payload) < 4:
        return None
    # `size` is not the complete number of bytes following this header. For example, Net 0x11
    # stores only the NetStation-array size there (6 * 22 = 0x84), while its 26-byte fixed prefix
    # is additional; Net 0x12 stores zero while its four-byte sequence id still follows. Return the
    # complete type-specific body and let the individual message parser interpret the size field.
    return payload[0], payload[1], payload[4:]


def build_net_response(seqid=2):
    """The joiner's Net connection response (the reference capture, message #2: 01 12 00 00 | <seqid:u32 BE>).
    The seqid ECHOES the host's 0x11 connection-request seqid (its body[0:4]); hardcoding 2 deadlocks the
    moment the host's network-status seqid differs (endless 500ms 0x11 retransmits -> host send-buffer fill)."""
    return bytes([0x01, NET_CONN_RESPONSE, 0x00, 0x00]) + (seqid & 0xFFFFFFFF).to_bytes(4, "big")


def ldn_constant_id(mac):
    """Derive Pia 6.x's 8-byte LDN constant id from a six-byte physical MAC."""
    mac = bytes(mac)
    if len(mac) != 6:
        raise ValueError("LDN constant id requires a 6-byte MAC")
    return bytes((mac[2], mac[4], mac[5], mac[3], mac[1], mac[0], 0, 0))


def _net_station(ip=None, port=12345, *, migration_state=0, migration_rank=0):
    """Build the fixed-size Pia 6.39 NetStation used by Net 0x11.

    Its StationAddress is a 16-byte address followed by a BE port. Native FRLG puts IPv4 in the
    first four bytes and zero-fills the remaining twelve. An empty slot uses rank 0xff and an all-zero
    address/port.
    """
    address = (_ip4(ip) + b"\x00" * 12) if ip is not None else b"\x00" * 16
    if ip is None:
        port = 0
    return (bytes([migration_state & 0xFF, migration_rank & 0xFF, 0, 0])
            + address + (port & 0xFFFF).to_bytes(2, "big"))


def build_net_conn_request(seqid, host_var, host_mac, network_id, stations, max_stations=6):
    """Build Pia 6.39 Net 0x11 (UpdateNetworkConnectionStatus).

    ``stations`` is an iterable of occupied IPs in join order (host first). Native FRLG always emits
    all configured slots and fills unused ones with rank 0xff. LDN's network id is a 32-bit SSID CRC
    carried in the protocol's 8-byte field as a zero-extended integer.
    """
    entries = list(stations)
    if not 1 <= len(entries) <= max_stations:
        raise ValueError("Net 0x11 needs 1..max_stations occupied station addresses")
    body = bytearray()
    body += (seqid & 0xFFFFFFFF).to_bytes(4, "big")
    body += (_vid(host_var) & 0xFFFF).to_bytes(2, "big")
    body += ldn_constant_id(host_mac)
    body += (network_id & 0xFFFFFFFF).to_bytes(8, "big")
    body += bytes([1])                              # network is open
    body += max_stations.to_bytes(2, "big")
    body += bytes([0])                              # not migrating host
    for rank, ip in enumerate(entries):
        body += _net_station(ip, migration_rank=rank)
    for _ in range(max_stations - len(entries)):
        body += _net_station(migration_rank=0xFF)
    station_array_size = max_stations * 22
    return bytes([0x01, NET_CONN_REQUEST]) + station_array_size.to_bytes(2, "big") + body


def build_net_property_ack(seqid):
    """Net 0x51 'Update network property' ACK (observed: 01 51 00 00 | <seqid:u32 BE>), echoing
    the host's 0x50 seqid. The host retransmits its 0x50 every 500ms until it sees this ack."""
    return bytes([0x01, NET_UPDATE_PROPERTY_ACK, 0x00, 0x00]) + (seqid & 0xFFFFFFFF).to_bytes(4, "big")


def parse_net_conn_request(payload):
    """Pull the host's identity out of a Net 0x11 connection request. The Net body is
    `[u32 ?][host var-id u16][host constant id = MAC(6) + 0000]...`; returns (host_var, host_mac).
    CRITICAL: the host's Pia CONSTANT ID is the emulator's fixed virtual GBA-adapter MAC
    (e5395b69d280 - identical across different physical Switches), NOT the console's LDN/WiFi MAC
    from the participant list. The Session join MUST address this constant id or the host ignores
    it. Learn it from the wire rather than from `network.info().participants`."""
    n = parse_net(payload)
    if not n or n[1] != NET_CONN_REQUEST or len(n[2]) < 12:
        return None
    body = n[2]
    # body[0:4] = the connection-request seqid (echoed in our 0x12); body[4:6]=host var; body[6:12]=host MAC.
    return int.from_bytes(body[4:6], "big"), bytes(body[6:12]), int.from_bytes(body[0:4], "big")


# --- RTT protocol (proto 3) -----------------------------------------------------------------
def parse_rtt(payload):
    """RTT message [wiki RTT-Protocol]: type is at BYTE 0x0 (0=request, 1=response); [0x4:0x8] padding,
    [0x8:0x10] system time, then (this title) [0x13:0x15] = subject var-id (21B total).
    CRITICAL: byte 0x3 is the RTT PROTOCOL VERSION (3 for Pia 5.29-5.44), NOT part of the
    type. The old code read the type as a u32-LE over [0:4] -> on this title that yields 0x03000000
    (version<<24), never 0/1, so we treated every host RTT REQUEST as 'not a request' and NEVER
    responded (0 RTT out vs native's ~1000). It only worked on the reference capture because there the
    version byte was 0. The host pings us for liveness; a station that never answers gets degraded/dropped."""
    if len(payload) < 16:
        return None
    return {"type": payload[0],                          # 0=request, 1=response (single byte)
            "version": payload[3],                       # RTT proto version (3 here); MUST be preserved
            "systime": payload[8:16],
            "subject": payload[19:21] if len(payload) >= 21 else b""}


def build_rtt_response(request):
    """Turn a host RTT request (type 0) into our response: type u32 = 1 LITTLE-ENDIAN (observed:
    01 00 00 00), echoing the rest of the request VERBATIM - the 12-byte timestamp so the host can
    compute the round-trip, and the subject [19:21] = host var 0x7620 (NOT our var). (The old code
    wrote type BE + subject=our_var, both wrong vs the reference capture.)"""
    b = bytearray(request[:21].ljust(21, b"\x00"))
    b[0] = 1                                          # type = response (BYTE 0); preserve [1:4] incl the
    return bytes(b)                                   # version byte [3]=3 and the host's timestamp (it
    # uses the echoed timestamp to compute the round-trip). Native does exactly this: OUT response bytes
    # are 01 00 00 03 (type 1 + version 3), i.e. the request with only byte 0 flipped.


def build_rtt_request(template, systime):
    """Originate a guest type-0 RTT request (~5.9/s on dst=0x0001). Clone the host's last request
    `template` (so the layout/subject are byte-faithful) and set type=0 (LE) with a fresh incrementing
    `systime`. The host echoes it in a type-1 response; matching the echoed systime to the send tick
    gives the round-trip that drives the reliable RTO (and keeps our slot live in the host's RTT layer)."""
    b = bytearray(template[:21].ljust(21, b"\x00"))
    b[0] = 0                                          # type = request (BYTE 0); preserve the template's
    b[8:16] = (systime & ((1 << 64) - 1)).to_bytes(8, "little")   # version byte [3] + layout, fresh systime
    return bytes(b)


# --- Session protocol (proto 13) ------------------------------------------------------------
def build_session_join(src_mac, src_var, src_ip, dst_mac, dst_var, player_name,
                       random4, *, src_port=12345, app_ver=DEFAULT_APP_VER,
                       protocols=DEFAULT_PROTOCOLS, player_id=DEFAULT_PLAYER_ID):
    """Build a Session(new) join request. src = the sim (joiner), dst = the host. var ids are
    2-byte BE; macs are 6 bytes. Reproduces the reference capture's message #3 exactly given its values."""
    out = bytearray([SESSION_JOIN_REQUEST, len(protocols)])
    for pid, ver in protocols:
        out += bytes([pid, ver])
    out += app_ver
    out += random4                                   # 4-byte random nonce
    out += bytes(src_mac) + b"\x00\x00"              # source constant id (8)
    out += bytes(src_var)                            # source variable id (2)
    out += bytes([0, 0])                             # NAT mapping, is-private-IPv6
    out += b"\x00" * 32                              # identification token
    out += bytes(dst_mac) + b"\x00\x00"             # dest constant id (8)
    out += bytes(dst_var)                            # dest variable id (2)
    out += bytes([1, 1])                             # num players, num participants
    out += bytes([0]) + _ip4(src_ip) + src_port.to_bytes(2, "big")   # StationAddress (IPv4)
    nm = player_name.encode()[:20]                   # PlayerInfo
    out += player_id + len(nm).to_bytes(4, "big") + bytes([1]) + nm
    return bytes(out)


def _constant_id8(value):
    value = bytes(value)
    if len(value) == 6:
        return value + b"\x00\x00"
    if len(value) != 8:
        raise ValueError("Pia constant id must be 6 or 8 bytes")
    return value


def _parse_player_info(payload, offset):
    if offset + 21 > len(payload):
        raise ValueError("truncated Session PlayerInfo")
    player_id = bytes(payload[offset:offset + 16])
    name_size = int.from_bytes(payload[offset + 16:offset + 20], "big")
    encoding = payload[offset + 20]
    end = offset + 21 + name_size
    if name_size > 40 or end > len(payload):
        raise ValueError("invalid Session PlayerInfo name size")
    return {
        "player_id": player_id,
        "encoding": encoding,
        "name": bytes(payload[offset + 21:end]),
    }, end


def parse_session_join(payload):
    """Parse a Pia 6.39 Session type-0 join request.

    The returned identity is sufficient for the leader's type-5 session update
    and type-2 join response.  Invalid or unsupported (non-IPv4) requests
    return ``None`` instead of letting malformed network input escape into the
    host loop.
    """
    payload = bytes(payload)
    try:
        if len(payload) < 2 or payload[0] != SESSION_JOIN_REQUEST:
            return None
        nprotocols = payload[1]
        pos = 2
        if pos + nprotocols * 2 + 2 + 4 + 8 + 2 + 2 + 32 + 8 + 2 + 2 > len(payload):
            return None
        protocols = [(payload[pos + i * 2], payload[pos + i * 2 + 1])
                     for i in range(nprotocols)]
        pos += nprotocols * 2
        app_ver = bytes(payload[pos:pos + 2]); pos += 2
        random4 = bytes(payload[pos:pos + 4]); pos += 4
        source_constant_id = bytes(payload[pos:pos + 8]); pos += 8
        source_var = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        nat_mapping, private_ipv6 = payload[pos], payload[pos + 1]; pos += 2
        token = bytes(payload[pos:pos + 32]); pos += 32
        destination_constant_id = bytes(payload[pos:pos + 8]); pos += 8
        destination_var = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        num_players, num_participants = payload[pos], payload[pos + 1]; pos += 2
        if pos >= len(payload) or payload[pos] != 0:       # FRLG LDN uses IPv4 here
            return None
        pos += 1
        if pos + 6 > len(payload):
            return None
        ip = ".".join(str(x) for x in payload[pos:pos + 4]); pos += 4
        port = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        players = []
        for _ in range(num_players):
            player, pos = _parse_player_info(payload, pos)
            players.append(player)
        if pos != len(payload):
            return None
        return {
            "protocols": protocols,
            "app_ver": app_ver,
            "random4": random4,
            "source_constant_id": source_constant_id,
            "source_var": source_var,
            "nat_mapping": nat_mapping,
            "private_ipv6": private_ipv6,
            "identification_token": token,
            "destination_constant_id": destination_constant_id,
            "destination_var": destination_var,
            "num_players": num_players,
            "num_participants": num_participants,
            "ip": ip,
            "port": port,
            "players": players,
        }
    except (IndexError, ValueError):
        return None


def _build_player_info(player_id, name, encoding=1):
    player_id = bytes(player_id)
    if len(player_id) != 16:
        raise ValueError("Pia player id must be 16 bytes")
    name = name.encode() if isinstance(name, str) else bytes(name)
    if len(name) > 40:
        raise ValueError("Pia player name is too long")
    return player_id + len(name).to_bytes(4, "big") + bytes([encoding]) + name


def _build_session_station(constant_id, variable_id, ip, port, station_index,
                           join_order, token, num_players, num_participants, players):
    token = bytes(token)
    if len(token) != 32:
        raise ValueError("Pia identification token must be 32 bytes")
    out = bytearray(_constant_id8(constant_id))
    out += (_vid(variable_id) & 0xFFFF).to_bytes(2, "big")
    out += _ip4(ip) + (port & 0xFFFF).to_bytes(2, "big")
    out += bytes([station_index & 0xFF])
    out += (join_order & 0xFFFF).to_bytes(2, "big")
    out += b"\x00\x00"                              # left-join order / reserved
    out += token
    out += bytes([num_players & 0xFF, num_participants & 0xFF])
    out += b"\x00\x00"
    for player in players:
        out += _build_player_info(player["player_id"], player["name"], player["encoding"])
    return bytes(out)


def build_session_update(join, host_constant_id, host_var, host_ip, host_name,
                         *, host_player_id=DEFAULT_PLAYER_ID, sequence_id=1):
    """Build the leader's fragmented Session type-5 acceptance/update.

    This is the two-station Pia 6.39 layout observed from the native FRLG
    leader.  The outer seven-byte fragment header declares one fragment; the
    body describes the leader first and the requesting station second.
    """
    if not join or not join.get("players"):
        raise ValueError("a parsed Session join with at least one player is required")
    host_constant_id = _constant_id8(host_constant_id)
    host_var = _vid(host_var)
    host_player = {"player_id": bytes(host_player_id), "name": host_name, "encoding": 1}
    host_station = _build_session_station(
        host_constant_id, host_var, host_ip, 12345, 0, 0, b"\x00" * 32, 1, 1,
        [host_player])
    guest_station = _build_session_station(
        join["source_constant_id"], join["source_var"], join["ip"], join["port"], 1, 1,
        join["identification_token"], join["num_players"], join["num_participants"],
        join["players"])
    # [type, unknown:u16, fragment-count, fragment-index, fragment-offset:u16]
    out = bytearray.fromhex("05000001000003")
    out += host_constant_id
    out += host_var.to_bytes(2, "big")
    out += bytes([2, 0])                            # two stations, no departed stations
    out += (sequence_id & 0xFFFF).to_bytes(2, "big")
    out += b"\x00" * 6                            # two documented + four 6.39 reserved bytes
    out += host_station + guest_station
    return bytes(out)


def build_session_join_response(join, host_constant_id, host_var, random4):
    """Build the leader's Session type-2 response for the first guest seat."""
    random4 = bytes(random4)
    if len(random4) != 4:
        raise ValueError("Session join response random value must be four bytes")
    versions = dict(join["protocols"])
    session_version = versions.get(PROTO_SESSION, 7)
    return (bytes([SESSION_JOIN_RESPONSE, PROTO_SESSION, session_version, 1])
            + b"\x00" * 4 + random4
            + _constant_id8(host_constant_id) + (_vid(host_var) & 0xFFFF).to_bytes(2, "big")
            + _constant_id8(join["source_constant_id"])
            + (join["source_var"] & 0xFFFF).to_bytes(2, "big")
            + bytes([1]) + (1).to_bytes(2, "big") + b"\x00\x00")


def parse_session(payload):
    """Light parse: surface the message type (and station count for a join response/update)."""
    if not payload:
        return None
    t = payload[0]
    rec = {"type": t}
    if t in (SESSION_JOIN_REQUEST, SESSION_UPDATE) and len(payload) > 2:
        rec["count"] = payload[1]
    return rec


# --- connection state machine (HOST-ACK-GATED; loss-tolerant) -------------------------------
# Header var-id (dst,src) progression observed in the reference capture:
#   net 0x12 -> (0, 0)   |   session join -> (0, our_var)   |   finalize/reliable -> (host_var, our_var)
# We never advance on our own send; we advance when the HOST acknowledges - it retransmits 0x11
# until it accepts our join, then sends a Session msg (-> we finalize), then RTT/Reliable (-> up).
# Because the host retransmits every stage and we answer each, a dropped OUT packet is simply
# re-sent on the host's next retransmit. Outbox entries carry their own (dst_var, src_var).
ST_NET, ST_FINALIZE, ST_CONNECTED = "net", "finalize", "connected"
# back-compat aliases
NET_WAIT, SESSION_WAIT, CONNECTED = ST_NET, ST_FINALIZE, ST_CONNECTED


def build_session_finalize(our_mac):
    """Session(13) type 6 - the joiner's finalize referencing ITS OWN constant id (the reference
    capture, message #14: 06 <our_mac:6> 0000 0000000000 01). The capture embeds the joiner's MAC here, not the host's."""
    return bytes([6]) + bytes(our_mac) + b"\x00\x00" + b"\x00" * 5 + bytes([1])


def _vid(x):
    return x if isinstance(x, int) else int.from_bytes(x, "big")


class ConnectionManager:
    """The S0 Pia connection as a host-ack-gated state machine. Outbox entries are
    (proto, payload, unicast, dst_var, src_var) - the var-ids change per stage."""

    def __init__(self, our_mac, host_mac, our_ip, host_ip, our_var=0xc493,
                 player_name="EMU", random4=b"\x00\x00\x00\x00", log=lambda *a: None):
        self.our_mac = bytes(our_mac)
        self.host_mac = bytes(host_mac)
        self.our_ip = our_ip
        self.host_ip = host_ip
        self.our_var = _vid(our_var)
        self.host_var = None
        self.player_name = player_name
        self.random4 = random4
        self.log = log
        self.info = getattr(log, "info", log)   # clean milestone sink (default-mode narration)
        self.state = ST_NET
        self._outbox = []
        # RTT origination: clone the host's last type-0 request as our template, bump a
        # systime per originated probe. _rtt_orig_tick gates the ~6/s cadence.
        self._last_host_rtt = None
        self._rtt_systime = 0x10000
        self._rtt_orig_tick = -10 ** 9
        # RTT measurement: each originated request's systime -> the tick it was sent, so the matching
        # type-1 response yields a round-trip. Completed round-trips (in ticks) accumulate in rtt_samples
        # for the caller to drain and feed into the reliable layer's RTO; the reliable RTO is RTT-driven.
        self._rtt_pending = {}
        self.rtt_samples = []

    def maybe_originate_rtt(self, tick):
        """Once connected, ORIGINATE a type-0 RTT request every RTT_ORIGINATE_PERIOD VBlanks (a liveness
        probe the host expects to see from us; it responds type-1, which we ignore). No-op
        until we have seen a host request to clone the layout from."""
        if not self.connected or self._last_host_rtt is None or self.host_var is None:
            return
        if tick - self._rtt_orig_tick < RTT_ORIGINATE_PERIOD:
            return
        self._rtt_orig_tick = tick
        self._rtt_systime = (self._rtt_systime + 1) & ((1 << 64) - 1)
        # remember when we sent this systime so the host's type-1 echo gives us the round-trip
        self._rtt_pending[self._rtt_systime] = tick
        if len(self._rtt_pending) > 64:                     # bound it if responses are being lost
            for k in sorted(self._rtt_pending, key=self._rtt_pending.get)[:32]:
                del self._rtt_pending[k]
        self._q(PROTO_RTT, build_rtt_request(self._last_host_rtt, self._rtt_systime),
                SESSION_VAR, self.our_var, False, True, False, footer_var=self.host_var)

    @property
    def connected(self):
        return self.state == ST_CONNECTED

    def learn_ids(self, our_var, host_var):
        if our_var is not None:
            self.our_var = _vid(our_var)
        if host_var is not None:
            self.host_var = _vid(host_var)

    def _join(self):
        return build_session_join(self.our_mac, self.our_var.to_bytes(2, "big"), self.our_ip,
                                  self.host_mac, (self.host_var or 0).to_bytes(2, "big"),
                                  self.player_name, self.random4)

    def _q(self, proto, payload, dst, src, compress, footer, establishing, pktid=None, footer_var=None):
        """Queue one outbox entry (a dict the sim frames per the wire rules). `pktid` overrides the
        sim's per-channel counter (the establishing connection-exchange frames force pktid=0).
        `footer_var` overrides the footer recipient when it differs from the header dst (RTT: header
        dst=0x0001 session channel, footer recipient=host var 0x7620)."""
        self._outbox.append({"proto": proto, "payload": payload, "dst": dst, "src": src,
                             "compress": compress, "footer": footer, "establishing": establishing,
                             "unicast": True, "pktid": pktid, "footer_var": footer_var})

    def on_message(self, proto, payload, tick=None):
        """React to a decoded IN Pia message; queue the ack-gated reply. The exact framing per stage:
          * Net 0x12   -> hdr(dst=0, src=0),                 establishing (pktid 0, flag 0x02), no footer, uncompressed.
          * Session join -> hdr(dst=0, src=OUR_var),         establishing, no footer, zstd-COMPRESSED.
          * Session finalize -> hdr(dst=host_var, src=our_var), established, footer=host_var, uncompressed.
          * RTT response -> hdr(dst=host_var, src=our_var),  established, footer=host_var, uncompressed."""
        if proto == PROTO_NET:
            n = parse_net(payload)
            if n and n[1] == NET_CONN_REQUEST and self.state == ST_NET:
                # The host's Net 0x11 carries its TRUE Pia constant id (emulator virtual MAC) + var
                # id; learn both from the wire (the participant-list MAC is a DIFFERENT identifier
                # and addressing it makes the host ignore our join). [parse_net_conn_request]
                req = parse_net_conn_request(payload)
                seqid = 2
                if req:
                    host_var, host_mac, seqid = req
                    self.host_mac = host_mac
                    if self.host_var is None:
                        self.host_var = host_var
                # answer EVERY host 0x11: Net 0x12 (ECHOING the 0x11 seqid) then the Session
                # join. Both are the establishing exchange -> pktid 0 on the dst=0x0000 channel (per the reference capture).
                self._q(PROTO_NET, build_net_response(seqid), 0, 0, False, False, True, pktid=0)
                if self.host_var is not None:
                    self._q(PROTO_SESSION, self._join(), 0, self.our_var, True, False, True, pktid=0)
            elif n and n[1] == NET_UPDATE_PROPERTY:
                # Mid-session 'Update network property' (in the reference capture: at the lobby->trade
                # transition). The host RETRANSMITS it every 500ms until it sees our Net 0x51 ack -> an
                # unanswered 0x50 keeps the host's reliable SEND buffer full (a leading BufferIsFull cause).
                # Echo the 0x50's seqid (its body[0:4]) in a Net 0x51 on dst=0x0000, establishing flag set.
                # NOTE: the reference capture used a "running" establishing pktid (173); we send a non-zero
                # per-channel pktid (unverified - confirm the host accepts it / stops retransmitting 0x50).
                body = n[2]
                seqid = int.from_bytes(body[0:4], "big") if len(body) >= 4 else 1
                self._q(PROTO_NET, build_net_property_ack(seqid), 0, self.our_var, False, False, True)
        elif proto == PROTO_SESSION:
            # host ACKED our join -> finalize (Session 6, dst=host, src=ours). Finalize ONLY on the
            # host's join-accept (Session type 5 / SESSION_UPDATE), NOT on every session message: the host
            # sends a type-5 accept (192B) AND a type-2 follow-up (37B), and we were finalizing on both (2
            # total) vs native's exactly ONE. Guarding on type 5 re-emits on a re-sent accept (loss
            # recovery) but never on the type-2, matching native. STOP once CONNECTED.
            s = parse_session(payload)
            if (s and s["type"] == SESSION_UPDATE
                    and self.host_var is not None and self.state != ST_CONNECTED):
                self._q(PROTO_SESSION, build_session_finalize(self.our_mac),
                        self.host_var, self.our_var, False, True, False)
            if self.state == ST_NET:
                self.state = ST_FINALIZE
                self.log("host acked join (Session) -> FINALIZE")
                self.info("Host acknowledged our join.")
        elif proto in (PROTO_RTT, PROTO_RELIABLE):
            if self.state == ST_FINALIZE:
                self.state = ST_CONNECTED
                self.log("host live (RTT/Reliable) -> CONNECTED")
                self.info("Connection established.")
            # Answer the host's RTT requests once we are past ST_NET (have finalized). The native does NOT
            # answer RTT during the pre-finalize window (byte-checked vs frlg2: zero RTT responses across the
            # whole 0.3-2.1s join), so we don't either - the pre-OK deadlock was NOT a liveness drop; it was
            # the connect-phase J/C reliable frames being sent once and never retransmitted (fixed via the
            # reliable layer's connect bootstrap RTO, sim.py RTO_BOOTSTRAP_MS).
            if proto == PROTO_RTT and self.state != ST_NET and self.host_var is not None:
                r = parse_rtt(payload)
                if r and r["type"] == 0:                  # host request -> respond
                    self._last_host_rtt = bytes(payload[:21])   # template for our own origination
                    self._q(PROTO_RTT, build_rtt_response(payload),
                            SESSION_VAR, self.our_var, False, True, False, footer_var=self.host_var)
                elif r and r["type"] == 1 and tick is not None:
                    # type-1 = the host echoing one of OUR originated requests. Match its systime to the
                    # tick we sent it and record the round-trip; this feeds the reliable RTO.
                    systime = int.from_bytes(r["systime"], "little")
                    sent = self._rtt_pending.pop(systime, None)
                    if sent is not None and tick >= sent:
                        self.rtt_samples.append(tick - sent)

    def drain(self):
        out, self._outbox = self._outbox, []
        return out
