#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Ethernet Trunk Guard
#
# This file is part of the Ethernet Trunk Guard distribution
# (https://github.com/aeburriel/trunkguard).
# Copyright (c) 2023 Antonio Eugenio Burriel <aeburriel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import annotations

import csv
import pcapy
import re

from collections import defaultdict
from datetime import datetime, timezone
from expiringdict import ExpiringDict
from queue import Full, Queue
from threading import Thread
from typing import Optional


class EthernetParser:
    ETHERNET_ENDIANNESS = "big"
    MIN_SIZE_HEADER = 14
    MIN_SIZE_VLAN_HEADER = 18

    def __init__(self, payload: bytes, device: str, timestamp: datetime):
        """Parses an Ethernet II or Ethernet 802.3 frame
        extracting the relevant characteristics.
        Partial frames are accepted if header is complete.

        Args:
            payload (bytes): raw frame
            device (str): capture device name
            timestamp (datetime): timestamp of capture

        Raises:
            ValueError: frame is too short
            ValueError: 802.1Q VLAN frame is too short
        """
        if len(payload) < self.MIN_SIZE_HEADER:
            raise ValueError("Ethernet frame too short")

        self.device = device
        self.dst = payload[0:6]
        self.src = payload[6:12]
        self.timestamp = timestamp

        self.type = getEtherType(int.from_bytes(
            payload[12:14], self.ETHERNET_ENDIANNESS))
        if self.type == 0x8100 or self.type == 0x88a8:
            # VLAN 802.1Q or QiQ 802.1ad
            if len(payload) < self.MIN_SIZE_VLAN_HEADER:
                raise ValueError("Ethernet VLAN frame too short")

            self.vlan = int.from_bytes(
                payload[14:16], self.ETHERNET_ENDIANNESS) & 0xfff
            self.type = getEtherType(int.from_bytes(
                payload[16:18], self.ETHERNET_ENDIANNESS))
        else:
            self.vlan = None

    def __str__(self) -> str:
        if self.vlan is not None and self.vlan >= 0:
            vlan = f"[VLAN {self.vlan}] "
        else:
            vlan = ""

        if self.type is None:
            type = "802.3"
        else:
            type = f"0x{self.type:04x}"

        return (f"{self.timestamp} {self.device} {vlan}{type}: "
                f"{mac2str(self.src)} → {mac2str(self.dst)}")

    def getDevice(self) -> str:
        """Return capturing device name

        Returns:
            str: device name
        """
        return self.device

    def getDst(self) -> bytes:
        """Return destination MAC Address

        Returns:
            bytes: 6 bytes MAC address
        """
        return self.dst

    def getDstStr(self) -> str:
        """Return destination MAC Address

        Returns:
            str: hex str representation
        """
        return mac2str(self.dst)

    @classmethod
    def getMinimumSize(cls) -> int:
        """Returns the minium packet capture size required

        Returns:
            int: minimum number of bytes to capture
        """
        return max(cls.MIN_SIZE_HEADER, cls.MIN_SIZE_VLAN_HEADER)

    def getSrc(self) -> bytes:
        """Return source MAC Address

        Returns:
            bytes: 6 bytes MAC address
        """
        return self.src

    def getSrcStr(self) -> str:
        """Return source MAC Address

        Returns:
            str: hex str representation
        """
        return mac2str(self.src)

    def getTimestamp(self) -> datetime:
        """Return capturing timestamp

        Returns:
            datetime: timestamp
        """
        return self.timestamp

    def getType(self) -> Optional[int]:
        """Return Ethernet II datagram type
        In case of VLAN 802.1Q datagram, it will return the encapsulated
        EtherType.

        Returns:
            Optional[int]: EtherType or None if unavailable (Ethernet 802.3)
        """
        return self.type

    def getVLAN(self) -> Optional[int]:
        """VLAN id if datagram is a 802.1Q datagram

        Returns:
            Optional[int]: VLAN number or None if datagram is not 802.1Q
        """
        return self.vlan

    def isbroadcast(self) -> bool:
        """Determine is frame is addressed to broadcast

        Returns:
            bool: true if destination is broadcast address
        """
        return self.dst == b'\xff\xff\xff\xff\xff\xff'

    def isDoubleVLAN(self) -> bool:
        """Determine if frame is double tagged (802.1ad QiQ)

        Returns:
            bool: true if QiQ
        """
        return isinstance(self.vlan, int) and self.type == 0x8100

    def isMulticast(self) -> bool:
        """Determine if frame is addressed to multicast

        Returns:
            bool: true if destination is a multicast address
        """
        return self.dst[0] & 1 == 1


class TrunkGuardContext:
    def __init__(self):
        # Discovered alien MAC addresses cache
        self.aliens = ExpiringDict(max_len=32768, max_age_seconds=600)
        # Source device description indexed by MAC
        self.descriptions = {}
        # Devices to listen to
        self.devices = set()
        # Whitelisted MAC set indexed by device and vlan
        self.macs = defaultdict(lambda: defaultdict(set))

    def addMAC(self, mac: bytes, device: str, vlan: Optional[int],
               description: Optional[str] = None):
        """Whitelist the specified MAC address for a network device and VLAN

        Args:
            mac (bytes): 6 bytes MAC address
            device (str): device name
            vlan (Optional[int]): VLAN or None if native
            description (Optional[str], optional): description of MAC address.
                                                   Defaults to None.
        """
        self.devices.add(device)

        if mac in self.macs[device][vlan]:
            print(f"WARNING: duplicated MAC {mac2str(mac)} "
                  f"for device {device} and VLAN {vlan}")
        else:
            self.macs[device][vlan].add(mac)

        if description is not None:
            if mac in self.descriptions.keys():
                print(f"WARNING: ignoring duplicated description "
                      f"'{description}' for MAC {mac2str(mac)}")
            else:
                self.descriptions[mac] = description

    def alertMAC(self, exception: MACTrunkGuardException):
        """Emit an alert for a frame

        Args:
            exception (MACTrunkGuardException): type of alert
        """
        src = exception.frame.getSrc()
        if src in self.aliens:
            self.aliens[src] = self.aliens[src] + 1
        else:
            print(exception)

            self.aliens[src] = 1

    def analyzer(self, frame: EthernetParser):
        """Process a frame

        Args:
            frame (EthernetParser): network frame to process
        """
        try:
            self.checkFrameStatus(frame)
        except UnauthorizedMAC as e:
            self.alertMAC(e)
        except UntrackedVLAN as e:
            self.alertMAC(e)

    def checkFrameStatus(self, frame: EthernetParser):
        """Tests frame against whitelist and other rules

        Args:
            frame (EthernetParser): captured frame

        Raises:
            UnknownDevice: unknown capturing device
            UntrackedVLAN: detected untracked VLAN traffic (no MAC whitelisted)
            UnauthorizedMAC: source MAC is not whitelisted
        """
        dev = self.macs.get(frame.getDevice(), None)
        if dev is None:
            # This should not ever happen
            raise UnknownDevice()

        vlan = dev.get(frame.getVLAN(), None)
        if vlan is None:
            raise UntrackedVLAN(frame)

        if frame.getSrc() in vlan:
            return

        raise UnauthorizedMAC(frame)

    def getDevices(self) -> set:
        """Return the listening devices set

        Returns:
            set: device names set
        """
        return self.devices

    def loadWhitelist(self, filename: str):
        """Load a MAC addresses whitelisting CSV file

        Args:
            filename (str): path to CSV file

        Raises:
            ValueError: missing MAC address
            ValueError: missing device name
        """
        with open(filename, "rt", newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter="\t",
                                quoting=csv.QUOTE_NONE,
                                skipinitialspace=True, strict=True)
            for row in reader:
                if len(row) == 0 or row[0].startswith("#"):
                    # Skip empty lines & commented lines
                    continue
                elif len(row) < 4:
                    # Exend row to all required fields
                    row += [""] * (4 - len(row))

                try:
                    mac = str2mac(row[0])
                    if mac is None:
                        raise ValueError(f"MAC address is mandatory "
                                         f"at line {reader.line_num}")
                    dev = row[1]
                    if len(dev) == 0:
                        raise ValueError(f"Device name is mandatory "
                                         f"at line {reader.line_num}")
                    vlan = str2int(row[2])
                    comment = row[3] if len(row[3]) > 0 else None

                    self.addMAC(mac, dev, vlan, comment)
                except IndexError:
                    print(f"Wrong number of columns. Skipping row "
                          f"at line {reader.line_num} '{row}'")
                except ValueError as e:
                    print(f"Incorrect value at line {reader.line_num}: {e}")


class Sniffer:
    def __init__(self, device: str, backlog: Queue, promiscuous: bool = True):
        """Initialize a Sniffer object

        Args:
            device (str): listening device
            backlog (Queue): work queue
            promiscuous (bool, optional): promiscuous mode. Defaults to False.

        Raises:
            TrunkGuardException: specified device is not Ethernet
        """
        self.device = device

        capture_size = EthernetParser.getMinimumSize()
        self.pcap = pcapy.open_live(self.device, capture_size, promiscuous, 0)
        if self.pcap.datalink() != pcapy.DLT_EN10MB:
            self.close()
            raise TrunkGuardException(f"Device {device} is not Ethernet")

        self.backlog = backlog

        print(f"Listening on device {device}")

    def close(self):
        """Close the capturing device
        """
        self.pcap.close()

    def process_frame(self, header, payload: bytes):
        """Enqueues captured frame

        Args:
            header (pcapy.Pkthdr): frame metadata
            payload (bytes): frame payload
        """
        try:
            timestamp = ts2datetime(*header.getts())
            frame = EthernetParser(payload, self.device, timestamp)
        except ValueError:
            pass
        try:
            self.backlog.put(frame)
        except Full:
            print("Backlog queue full, discarding datagram")

    def start(self):
        """Start capturing loop
        """
        self.pcap.loop(0, self.process_frame)


# TrunkGuard Exceptions

class TrunkGuardException(Exception):
    pass


class MACTrunkGuardException(TrunkGuardException):
    def __init__(self, frame: EthernetParser):
        self.frame = frame

        super().__init__(f"{self.__class__.__name__}: {self.frame}")


class UnauthorizedMAC(MACTrunkGuardException):
    pass


class UnknownDevice(TrunkGuardException):
    pass


class UntrackedVLAN(MACTrunkGuardException):
    pass


class VLANInVLAN(MACTrunkGuardException):
    pass


# Auxiliary Functions

def getEtherType(ets: int) -> Optional[int]:
    """Returns EtherType for the specified EtherType/Size value

    Args:
        ets (int): Ethernet II EtherType or Ethernet 802.3 size field

    Returns:
        Optional[int]: EtherType or None if value is a 802.3 size field
    """
    return ets if ets >= 1536 else None


def mac2str(mac: bytes) -> str:
    """Converts a binary MAC address to its text representation

    Args:
        mac (bytes): MAC address 6 bytes long

    Returns:
        str: textual representation
    """
    return mac.hex(":")


RE_MAC_VALIDATE = re.compile(r"^([0-9a-f]{2}:){5}([0-9a-f]{2})"
                             r"|([0-9a-f]{2}-){5}([0-9a-f]{2})"
                             r"|([0-9a-f]{4}\.){2}([0-9a-f]{4})"
                             r"|([0-9a-f]{12})$", re.IGNORECASE)
RE_MAC_SEPARATORS = re.compile(r"[\.:\-]")


def str2mac(mac: str) -> bytes:
    """Converts a text hex MAC address to its binary representation

    Args:
        mac (str): MAC address 6 bytes long

    Raises:
        ValueError: string does not represent a valid 6 bytes MAC address

    Returns:
        bytes: binary representation
    """
    if RE_MAC_VALIDATE.match(mac) is None:
        raise ValueError(f"'{mac}' is not a valid MAC address")

    return bytes.fromhex(RE_MAC_SEPARATORS.sub("", mac))


def str2int(text: str, lower: Optional[int] = 0,
            upper: Optional[int] = 4095) -> Optional[int]:
    """Convert a number as decimal string to int

    Args:
        text (str): string to process
        lower (Optional[int], optional): lower allowed value. Defaults to 0.
        upper (Optional[int], optional): upper allowed value. Defaults to 4095.

    Raises:
        ValueError: string does not represent a valid decimal integer
        ValueError: out of bounds value

    Returns:
        Optional[int]: int or None if string is empty or '-'
    """
    if len(text) == 0 or text == "-":
        return None

    try:
        value = int(text)
    except ValueError:
        raise

    if lower <= value <= upper:
        return value

    raise ValueError(f"Out of bounds for value {value}. "
                     f"It must be between {lower} and {upper}")


def ts2datetime(seconds: int, microseconds: int) -> datetime:
    """Convert a (seconds, microseconds) timestamp since Epoch
    to UTC datetime object

    Args:
        seconds (int): seconds since epoch
        microseconds (int): microseconds part

    Returns:
        datetime: UTC datetime object
    """
    # https://blog.ganssle.io/articles/2019/11/utcnow.html
    return datetime.fromtimestamp(seconds + microseconds * 1e-6,
                                  tz=timezone.utc)


# TrunkGuard Logic

def sniffer_loop(backlog: Queue, device: str):
    """Sniffing loop

    Args:
        backlog (Queue): pending frames queue
        device (str): capturing device name
    """
    pcap = Sniffer(device, backlog)
    pcap.start()


def warden_loop(backlog: Queue, context: TrunkGuardContext):
    """Processing loop

    Args:
        backlog (Queue): pending frames queue
        context (TrunkGuardContext): internal context
    """
    while True:
        frame = backlog.get()
        context.analyzer(frame)
        backlog.task_done()


# TrunkGuard Main Program

if __name__ == "__main__":
    context = TrunkGuardContext()
    context.loadWhitelist("whitelist.csv")

    # Backlog queue
    backlog = Queue(maxsize=1000)

    # Deploy sniffer workers
    sniffers = [
        Thread(target=sniffer_loop, args=(backlog, device))
        for device in context.getDevices()
    ]

    # Deploy processing worker
    warden = Thread(target=warden_loop, args=(backlog, context))

    # Start workers
    warden.start()
    for sniffer in sniffers:
        sniffer.start()

    # Wait for jobs
    for sniffer in sniffers:
        sniffer.join()
    warden.join()
