from __future__ import annotations

import contextlib
import logging
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from multiprocessing import Manager, Process
from multiprocessing.managers import DictProxy, ListProxy
from typing import TYPE_CHECKING

import pydivert

from network.sessioninfo import SessionInfo
from util.console import get_original_console_title, set_console_title
from util.dynamicblacklist import T2_EU_FALLBACK, T2_US_FALLBACK
from util.network import construct_cidr_block_set, ip_in_cidr_block_set
from util.types import CIDR_BLOCK

if TYPE_CHECKING:
    # PipeConnection only exists on Windows; only needed for type hints.
    from multiprocessing.connection import PipeConnection

logger = logging.getLogger(__name__)
debug_logger = logging.getLogger("debugger")

# It appears that there is *ONE* more problem we may need to take care of which was missed during testing of the prototype.
# Apparently, it's not only R* tunnels, but also client tunnels! If the circumstances are right, then it turns out that
# people in your session can also tunnel players if they could not connect to you directly. Such is the joy of P2P
# gaming.

# This conundrum could be easily solved with packet inspection but I'm going go back on my previous words and try to
# solve this by filtering some outbound packets, as it's the only solution I can think of.

# My idea is that if we receive a matchmaking request (or what could be a matchmaking request), then we will temporarily
# drop responses from us to any other client in the session. This, again, will have to be guessed from the payload size.
# Currently, I have no idea whether the responses to matchmaking requests are unique enough to be blocked without risking
# dropping other game traffic from someone who is actually in the session.

# It's possible that this behaviour can be mitigated by making the whitelist filter "air-tight" as there was a bug in the
# official build which was leaking packets. However, if this bug is reported significantly in testing then I'll go ahead
# and develop my theoretical solution.

# The main flaw in Guardian lied here, in the reserved IP range. I believe this is the R* / T2 IP space, right?
# In the current public build, any packet from these IPs is allowed, but we can no longer do this. We have to block
# tunnelled connections which may come from this IP range, while still allowing certain services like the
# session heartbeat and matchmaking requests.

# Currently, my proof-of-concept does not discern whether a heartbeat has come from a R* / T2 IP as I have not been able
# to confirm if that actually is the case. Ideally, ipfilter should be a range of all IPs that can send heartbeats
# and / or matchmaking requests, and so the checks for packet sizes will be done only if the packet has come from an IP
# in the ipfilter range.

# So, ipfilter's usage has been removed from the Whitelist class. I didn't completely remove it because I think it would
# still be useful to compare how the new rules can drop tunnels while still letting heartbeats and matchmaking through.

ipfilter = re.compile(r"^(185\.56\.6[4-7]\.\d{1,3})$")

# I decided to filter only on packets inbound to 6672 because most of the new filtering logic only checks inbound packets,
# and I don't think it makes much sense to add extra load by checking outbound packets when we're not doing
# anything interesting with them at the moment. I also found the packet payload sizes to be more consistent when coming
# from R*-owned resources instead of looking at the responses to those requests.
# I also believe that strictly filtering on inbound helps the game remain unaware that packets are being filtered and
# this might mean that the game will probably behave in a more consistent manner.
# (If the game was aware packets weren't reaching clients, it may change its behaviour)

# NOTE: If R* ever updates Online to support IPv6, then "and ip" should be removed from packetfilter,
# and parts of the filter logic (in the Whitelist class) that use the packet.ip attribute should be changed.

# PACKET_FILTER = "udp.SrcPort == 6672 or udp.DstPort == 6672 and ip"
GTA_PORT = 6672
# Rockstar's documented extra GTA Online UDP ports. The payload-size heuristics (heartbeat / matchmaking)
# were only observed on 6672, so on these ports Rockstar/Take-Two ranges are never blocked and the
# size heuristics are not applied. Can be disabled with "extra_ports": false in data.json.
EXTRA_PORTS = frozenset(range(61455, 61459))
ALL_PORTS = frozenset({GTA_PORT}) | EXTRA_PORTS

PACKET_FILTER_6672_ONLY = "udp and udp.DstPort == 6672 and udp.PayloadLength > 0 and ip"
PACKET_FILTER = (
    "udp and (udp.DstPort == 6672"
    " or (inbound and udp.DstPort >= 61455 and udp.DstPort <= 61458))"
    " and udp.PayloadLength > 0 and ip"
)


def packet_filter(extra_ports: bool = True) -> str:
    """Strict filter: UDP to exactly 6672 (+ inbound 61455-61458 if enabled), nothing else."""
    return PACKET_FILTER if extra_ports else PACKET_FILTER_6672_ONLY


def extra_ports_enabled() -> bool:
    """Config option "extra_ports" (default True). Any config error -> default."""
    try:
        from config.configdata import ConfigData

        return bool(ConfigData().data.get("extra_ports", True))
    except Exception:
        return True


ROCKSTAR_BLOCKS: set[CIDR_BLOCK] = construct_cidr_block_set(
    sorted(T2_EU_FALLBACK | T2_US_FALLBACK)
)


def is_rockstar_ip(ip: str) -> bool:
    return ip_in_cidr_block_set(ip, ROCKSTAR_BLOCKS)


def is_extra_port(packet: pydivert.Packet) -> bool:
    """Inbound packet to 61455-61458 (outbound traffic on these ports is never filtered)."""
    return bool(packet.is_inbound) and packet.dst_port in EXTRA_PORTS


class FilterOpenError(Exception):
    """The WinDivert handle could not be opened with the packet filter."""


@contextlib.contextmanager
def open_windivert(
    flags: pydivert.Flag | None = None, priority: int = 0, filter_: str = PACKET_FILTER
) -> Iterator[pydivert.WinDivert]:
    """Open a WinDivert handle on the strict filter; any open failure -> FilterOpenError."""
    try:
        handle = pydivert.WinDivert(
            filter_, priority=priority, flags=flags or pydivert.Flag.DEFAULT
        )
        handle.open()
    except Exception as e:
        raise FilterOpenError(
            f"WinDivert open failed for filter {filter_!r}: {e}"
        ) from e
    try:
        yield handle
    finally:
        if handle.is_open:
            handle.close()


def probe_filter(extra_ports: bool = True) -> None:
    """Open and immediately close a sniff handle to validate filter + driver at startup."""
    with open_windivert(pydivert.Flag.SNIFF, filter_=packet_filter(extra_ports)):
        pass


# Based on network observation, the payload sizes of packets which are probably some sort of heartbeat (and therefore
# should be let through so the session stays online), or a matchmaking request (and therefore should be let through so we
# can see who's attempting to connect to us).

# Interesting note: All the matchmaker requests have payload sizes that may be 16 bytes apart.

HEARTBEAT_SIZES = {12, 18, 63}
MATCHMAKING_SIZES = {
    191,
    207,
    223,
    239,
}  # probably a player looking to join the session.
DTLs = {0xFEFF, 0xFEFD}
KNOWNS = {0x39, 0x31, 0x29}
# RECORDS = {20, 21, 22, 23}


KNOWN_SIZES = HEARTBEAT_SIZES.union(MATCHMAKING_SIZES)

# Matchmaking response sizes might be: 45, 125, 205?
# The size 45 payload definitely cannot be blocked as it pops up frequently in normal gameplay.
# It appears that the 125 and 205 packets also pop up from time to time.
# The first *two* packets sent to a client joining do appear to be size 125 and 205, though. Hmmm...
# So the initial join response appears to be 125, 205, 45, 317, 493?

# Looks like blocking 205 inbound is our best bet. 493 outbound is also a possibility but probably has a chance of
# accidentally dropping the client non-tunnels.

# After I wrote these comments it was discovered that Guardian wasn't filtering packets all the time. This bug has since
# been fixed and hopefully will also mean these "client tunnels" are now no longer an issue. Leaving these notes in just
# in case they're useful later on.


# VOLONTAIRE — repris tel quel du Guardian d'origine (3.5.0). En mode Liste blanche, cette
# fonction lit seulement quelques octets d'en-tête de paquets UDP chiffrés pour reconnaître
# les services Rockstar et les laisser passer. Elle n'enregistre rien, n'affiche rien et ne
# lit pas le jeu (ni sa mémoire, ni ses fichiers, ni le contenu déchiffré des paquets).
def is_whitelist_service_packet(payload: bytes) -> bool:
    """
    Heuristic (from upstream 3.5.0) recognising R* service / DTLS-handshake style packets by
    de-obfuscating a few header bytes of the (encrypted) payload. Pure function so it can be unit tested.

    Upstream read the "wrapper" from packet.raw[28:30], i.e. the first two payload bytes assuming a
    20-byte IPv4 header; payload[0:2] is equivalent and robust to IP options. Payloads shorter than
    5 bytes used to raise IndexError and kill the filter process; they are now simply not matched.
    """
    size = len(payload)
    if size < 5:
        return False

    wrapper = int.from_bytes(payload[0:2], "big")
    if size != wrapper:
        return False

    magic_byte = payload[4]
    offset = payload[2] ^ magic_byte
    code = 0
    alt = 0
    if offset == 17 and size >= 27:
        code = int.from_bytes(payload[25:27], "big")
        alt = payload[24]
    elif offset == 49 and size >= 91:
        code = int.from_bytes(payload[89:91], "big")

    magic = int.from_bytes(bytes([magic_byte, magic_byte]), "big")
    return (
        (code ^ magic) in DTLs or (alt ^ magic_byte) in KNOWNS or (code ^ magic) < 0x10
    )


class AbstractPacketFilter(ABC):
    def __init__(
        self,
        ips: set[str],
        priority: int,
        connection: PipeConnection,
        session_info: SessionInfo | None = None,
        debug: bool = False,
    ):
        self.ips = ips
        self.priority = priority
        self.queue = connection
        self.process = Process(target=self.run, daemon=True)
        self.session_info = session_info
        self.debug_print_decisions = debug
        self.extra_ports = extra_ports_enabled()

    def __str__(self) -> str:
        return f"{self.__class__.__name__} with priority {self.priority}"

    def start(self) -> None:
        self.process.start()
        logger.info("Dispatched %s blocker process", self.__class__.__name__)
        set_console_title(f"{get_original_console_title()} - {self.__class__.__name__}")

    def stop(self, overwrite_title: bool = True) -> None:
        self.process.terminate()
        logger.info("Terminated %s blocker process", self.__class__.__name__)
        if overwrite_title:
            set_console_title(get_original_console_title())

    @abstractmethod
    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        pass

    def on_started(self) -> None:
        """Appelé dans le processus de filtrage, une fois le handle WinDivert ouvert."""
        return None

    def finished(self) -> bool:
        """True = le filtre a terminé son travail : la boucle s'arrête et le handle
        WinDivert est fermé (le trafic redevient normal, sans Guardian)."""
        return False

    def run(self) -> None:
        with contextlib.suppress(KeyboardInterrupt):
            self.queue.send(True)
            with open_windivert(
                priority=self.priority, filter_=packet_filter(self.extra_ports)
            ) as w:
                self.on_started()
                for packet in w:
                    decision = self.is_packet_allowed(packet)
                    if decision:
                        w.send(packet)

                    if self.session_info is not None:
                        self.session_info.add_packet(packet, allowed=decision)

                    if self.debug_print_decisions:
                        print(self.construct_debug_packet_info(packet, decision))

                    if self.finished():
                        break

    @staticmethod
    def construct_debug_packet_info(
        packet: pydivert.Packet, decision: bool | None = None
    ) -> str:
        prefix = "" if decision is None else ("ALLOWING" if decision else "DROPPING")

        return f"{prefix} PACKET FROM {packet.src_addr}:{packet.src_port}  Len: {len(packet.payload)}"


class SoloSession(AbstractPacketFilter):
    """
    Packet filter that does not allow join requests at all. Previously, Solo Session was actually just
    "Whitelisted" with an empty list. This variant is technically more secure if you truly don't want anything
    connecting to your client except the heartbeat.
    """

    def __init__(
        self,
        priority: int,
        connection: PipeConnection,
        session_info: SessionInfo | None = None,
        debug: bool = False,
    ):
        super().__init__(set(), priority, connection, session_info, debug)

    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        if is_extra_port(packet):
            # No size heuristics on 61455-61458: only Rockstar/T2 servers get through.
            return is_rockstar_ip(packet.ip.src_addr)
        size = len(packet.payload)

        return size in HEARTBEAT_SIZES


# « Session publique en hôte au départ » : durée FIXE de la phase solo (secondes).
# Volontairement non réglable (ni option, ni touche).
HOST_FIRST_SECONDS = 60
# Message envoyé par le processus de filtrage quand il est réellement lancé.
HOST_FIRST_STARTED = "host_first_started"
# Message envoyé si l'ouverture du handle WinDivert échoue : (HOST_FIRST_FAILED, raison).
HOST_FIRST_FAILED = "host_first_failed"


class HostFirstSession(SoloSession):
    """Phase 1 (HOST_FIRST_SECONDS) : filtrage SoloSession inchangé (les joins entrants
    sont jetés). Phase 2 : réouverture automatique, simple transfert sans blocage, puis
    fermeture du handle WinDivert. Uniquement du drop : aucun paquet créé ni modifié."""

    def __init__(
        self,
        priority: int,
        connection: PipeConnection,
        session_info: SessionInfo | None = None,
        debug: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ):
        super().__init__(priority, connection, session_info, debug)
        # Horloge MONOTONE (insensible aux changements d'heure du système).
        self.clock = clock
        # On transmet une DURÉE, pas un instant : le processus de filtrage réarme son
        # propre échéancier au démarrage (run), sans dépendre d'une horloge partagée
        # entre processus. Le compte à rebours de l'affichage utilise celui-ci.
        self.duration = float(HOST_FIRST_SECONDS)
        self.open_at = clock() + self.duration

    def run(self) -> None:
        self.open_at = self.clock() + self.duration
        self._started = False
        try:
            super().run()
        except Exception as e:
            if not self._started:
                # Handle WinDivert non ouvert : on prévient le menu, qui n'affichera
                # ni « Session ouverte » ni compte à rebours.
                with contextlib.suppress(Exception):
                    self.queue.send((HOST_FIRST_FAILED, f"{type(e).__name__}: {e}"))
            raise

    def on_started(self) -> None:
        self._started = True
        # Filtre réellement actif : l'échéance part de MAINTENANT, et le menu est
        # prévenu par le Pipe existant (durée restante, pas d'instant d'horloge).
        self.open_at = self.clock() + self.duration
        with contextlib.suppress(Exception):
            self.queue.send((HOST_FIRST_STARTED, self.duration))

    def is_open(self) -> bool:
        return self.clock() >= self.open_at

    def remaining(self) -> float:
        return max(0.0, self.open_at - self.clock())

    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        if self.is_open():
            return True  # phase 2 : session publique normale
        return super().is_packet_allowed(packet)

    def finished(self) -> bool:
        return self.is_open()


class WhitelistSession(AbstractPacketFilter):
    """
    Packet filter that will allow packets from with source ip present on ips list

    ips: A set of whitelisted IPs.
    """

    def __init__(
        self,
        ips: set[str],
        priority: int,
        connection: PipeConnection,
        session_info: SessionInfo | None = None,
        debug: bool = False,
    ):
        super().__init__(ips, priority, connection, session_info, debug)

    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        ip = packet.ip.src_addr
        size = len(packet.payload)

        if is_extra_port(packet):
            return ip in self.ips or is_rockstar_ip(ip)

        # The "special sauce" for the new filtering logic. We're using payload sizes to guess if the packet
        # has a behaviour we want to allow through.
        if ip in self.ips or size in HEARTBEAT_SIZES:
            return True

        return is_whitelist_service_packet(bytes(packet.payload))


class BlacklistSession(AbstractPacketFilter):
    """
    Packet filter that will block packets from with source ip present on ips list
    """

    def __init__(
        self,
        ips: set[str],
        priority: int,
        connection: PipeConnection,
        blocks: set[CIDR_BLOCK] | None = None,
        known_allowed: set[str] | None = None,
        session_info: SessionInfo | None = None,
        debug: bool = False,
    ) -> None:
        super().__init__(ips, priority, connection, session_info, debug)

        if blocks is None:
            blocks = set()
        if known_allowed is None:
            known_allowed = set()

        self.ip_blocks = blocks  # set of CIDR blocks
        self.known_allowed = known_allowed  # IPs which are known to not be in blocks

    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        ip = packet.ip.src_addr
        size = len(packet.payload)

        if is_extra_port(packet) and is_rockstar_ip(ip):
            return True
        if ip in self.known_allowed or (
            not is_extra_port(packet) and size in KNOWN_SIZES
        ):
            return True
        elif ip not in self.ips:
            # If it's not directly blacklisted it might be in a blacklisted range
            if ip_in_cidr_block_set(ip, self.ip_blocks):
                # It was in a blacklisted range, add this to the standard list
                self.ips.add(ip)
                return False
            else:
                # If not then it's definitely allowed, remember this for next time
                self.known_allowed.add(ip)
                return True
        return False


class LockedSession(AbstractPacketFilter):
    """
    Packet filter to block all join request packets and i.e. any new attempts to connect to your client.
    Any existing connections do not get blocked. Locked is the only way to firewall a session off if one
    or more of those players are not directly routed to the Session Host (i.e. you).
    """

    def __init__(
        self,
        priority: int,
        connection: PipeConnection,
        session_info: SessionInfo | None = None,
        debug: bool = False,
    ):
        super().__init__(set(), priority, connection, session_info, debug)

    def is_packet_allowed(self, packet: pydivert.Packet) -> bool:
        if is_extra_port(packet):
            # Matchmaking sizes were only observed on 6672: never block on extra ports.
            return True
        size = len(packet.payload)

        # No new matchmaking requests allowed.
        # Seems a bit overkill (and perhaps reckless) to always block these payload sizes but my packet
        # captures show that these payload sizes don't occur in any regular game traffic so...
        return size not in MATCHMAKING_SIZES


# TODO: Convert this to AbstractPacketFilter
class DebugSession:
    """
    Thread to create a log of the ips matching the packet filter
    """

    def __init__(self, ips: set[str], priority: int):
        self.extra_ports = extra_ports_enabled()
        self.ips = ips
        self.priority = priority
        self.process = Process(target=self.run, daemon=True)

    def start(self) -> None:
        self.process.start()

    def stop(self) -> None:
        self.process.terminate()

    def run(self) -> None:
        debug_logger.debug("Started debugging")
        with open_windivert(
            pydivert.Flag.SNIFF, self.priority, packet_filter(self.extra_ports)
        ) as w:
            for packet in w:
                dst = packet.ip.dst_addr
                src = packet.ip.src_addr
                size = len(packet.payload)
                whitelisted = False
                reserved_allow = False  # Packet from a reserved IP was allowed.
                reserved_block = False  # Packet from a reserved IP was blocked.
                service = False  # Packet allowed because it could be heartbeat / matchmaker but not from a reserved IP.
                if ipfilter.match(dst) or ipfilter.match(src):
                    if size in KNOWN_SIZES:
                        reserved_allow = True
                    else:
                        reserved_block = True  # Came from a "reserved" IP but was blocked under the new rules.
                elif dst in self.ips or src in self.ips:
                    whitelisted = True
                elif size in KNOWN_SIZES:
                    service = True  # Was allowed because it may be service-related, but wasn't from a reserved IP.

                if whitelisted:
                    filler = "Whitelist"
                elif reserved_allow:
                    filler = "Reserved (Allowed)"
                elif reserved_block:
                    filler = "Reserved (Blocked)"
                elif service:
                    filler = "Service (Allowed)"
                else:
                    filler = "Blocked"

                debug_logger.debug(
                    "[%s] %s:%s %s %s:%s",
                    filler,
                    src,
                    packet.src_port,
                    "-->" if packet.is_inbound else "<--",
                    dst,
                    packet.dst_port,
                )


# Okay, so there's a couple of changes that need to be done to fix auto-whitelisting.

# The main flaw is that this IPCollector has a chance of collecting IPs that are responsible for R* Services
# (and can i.e. be used for tunnelling).
# When you're in a session, a R* Service will "ping" your session / check for a "heartbeat". If your session is pinged
# while the IPCollector is running, the IPCollector will add the source of that ping to the whitelist.

# This wasn't a problem before Online 1.54 because these services weren't used for tunneling connections. But, now, if
# a player joining the session cannot connect to you directly, these IPs can be used for R* Services *can* be used for
# tunnelled session traffic. As the IPCollector has added these R* Service IPs to the whitelist, tunnelled connections are
# now also whitelisted, which obviously breaks session security.

# The first fix is to adjust the rules / "reasons" the IPCollector may add an IP to the auto-whitelist.
# Because the new filters only filter inbound traffic, I have decided to only add an IP to the auto-whitelist if:
#   - the packet is inbound
#   - the packet does not contain a payload size equal to a heartbeat
#   - the packet does not contain a payload size equal to a matchmaking request

# There is one more check we need to perform, which will be done *after* the IP collector has run, mainly due to the extra
# complexity required to perform it.
# My research indicates that R* uses Microsoft Azure Cloud for most of their R* Services. Microsoft frequently publishes
# their IP ranges used for cloud activity. As a last safe-guarding step, we should acquire these IP ranges and ensure that
# collected IPs do not correspond to any cloud traffic.

# If the new version of the IPCollector has saved an IP address used by Azure, this almost certainly guarantees that
# someone is already being tunnelled through a R* Service (as using Azure for VPNs is incredibly rare), and we will need
# to display a warning that these players must be dropped from the session for security to remain.

# There are some extra heuristics we could also add to the IPCollector, such as actually noting any IPs that might be
# R* Services by checking their payload sizes, running the auto-whitelist service for a whole 60 seconds (!), and also
# only adding IPs which have sent a certain threshold of packets during the IP collection phase. (When in a session, you
# send a *significant* amount of packets between clients, compared to only a handful of packets for other misc. activity.)


class IPCollector:
    """
    Thread to store all the ip addresses matching the packet filter
    """

    def __init__(self, priority: int, packet_count_min_threshold: int = 1):
        self.extra_ports = extra_ports_enabled()
        self.priority = priority
        self.process = Process(target=self.run, daemon=True)
        self.ips: ListProxy[str] = Manager().list()
        self.seen_ips: DictProxy[str, int] = (
            Manager().dict()
        )  # key is IP address, value is packets seen
        self.min_packets = packet_count_min_threshold  # minimum amount of packets required to be seen to be added

    def add_seen_ip(self, ip: str) -> None:
        """
        Keeps a "counter" of how many packets have been seen from this IP.
        """
        self.seen_ips[ip] = self.seen_ips.get(ip, 0) + 1

    def save_ips(self) -> None:
        """
        Saves any IP that has been seen at least self.min_packets times.
        """
        for ip in self.seen_ips:
            if self.seen_ips[ip] >= self.min_packets:
                self.ips.append(ip)

    def start(self) -> None:
        self.process.start()
        logger.info("Dispatched IPCollector process")

    def stop(self) -> None:
        self.process.terminate()
        logger.info("Terminated IPCollector process")
        self.save_ips()
        logger.info("Collected a total of %d IPs", len(self.ips))

    def run(self) -> None:
        # TODO: We could also actually check to see *when* the last packet was seen from that IP.
        with (
            contextlib.suppress(KeyboardInterrupt),
            open_windivert(
                pydivert.Flag.SNIFF, self.priority, packet_filter(self.extra_ports)
            ) as w,
        ):
            for packet in w:
                size = len(packet.payload)

                if packet.is_inbound and size not in KNOWN_SIZES:
                    src = packet.ip.src_addr
                    self.add_seen_ip(src)
