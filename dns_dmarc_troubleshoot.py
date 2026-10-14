#!/usr/bin/env python3
"""Check whether a domain publishes a DMARC TXT record.

Asks for a full domain name such as example.com, then queries
_dmarc.<domain>. A name that already starts with _dmarc. is queried
as entered.
"""

import random
import socket
import struct
import sys
import winreg
from urllib.parse import urlparse


def clean_text(text, fallback):
    flattened = " ".join((text or "").split())
    return flattened or fallback


def dmarc_query(raw):
    name = raw.strip()
    if "://" in name:
        name = urlparse(name).hostname or ""
    name = name.strip().rstrip(".")
    if not name or "." not in name or any(ch.isspace() or ch == "/" for ch in name):
        raise ValueError("Enter a full domain name such as example.com")

    if name.lower().startswith("_dmarc."):
        display = name.split(".", 1)[1]
        query = name
    else:
        display = name
        query = "_dmarc." + name
    return display, ascii_name(query)


def ascii_name(name):
    labels = []
    for label in name.split("."):
        if not label or len(label) > 63:
            raise ValueError("Enter a full domain name such as example.com")
        labels.append(label if label.isascii() else label.encode("idna").decode("ascii"))
    encoded = ".".join(labels)
    if len(encoded) > 253:
        raise ValueError("Enter a full domain name such as example.com")
    return encoded


def dns_servers():
    servers = []

    def add(raw):
        for part in str(raw).replace(",", " ").split():
            if part and part not in servers:
                servers.append(part)

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        ) as key:
            for value_name in ("NameServer", "DhcpNameServer"):
                try:
                    add(winreg.QueryValueEx(key, value_name)[0])
                except FileNotFoundError:
                    pass
    except OSError:
        pass

    try:
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                with winreg.OpenKey(root, winreg.EnumKey(root, index)) as key:
                    for value_name in ("NameServer", "DhcpNameServer"):
                        try:
                            add(winreg.QueryValueEx(key, value_name)[0])
                        except FileNotFoundError:
                            pass
    except OSError:
        pass

    return servers


def build_query(qname):
    transaction = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in qname.split(".")
        if label
    )
    return transaction, header + question + b"\x00" + struct.pack(">HH", 16, 1)


def read_name(packet, offset):
    labels = []
    seen = set()
    jumped = False
    consumed = offset
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                consumed = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen or pointer >= len(packet):
                raise ValueError("bad DNS pointer")
            seen.add(pointer)
            if not jumped:
                consumed = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        end = offset + length
        if end > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset:end].decode("ascii", "replace"))
        offset = end
        if not jumped:
            consumed = offset
    return ".".join(labels), consumed


def parse_txt(packet, transaction):
    if len(packet) < 12:
        raise ValueError("short DNS response")
    response_id, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", packet[:12])
    if response_id != transaction:
        raise ValueError("DNS response id did not match")
    if flags & 0x0200:
        raise TimeoutError("DNS response was truncated")
    offset = 12
    for _ in range(questions):
        _, offset = read_name(packet, offset)
        offset += 4
    texts = []
    for _ in range(answers):
        _, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer")
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        if rtype != 16 or rclass != 1:
            continue
        parts = []
        index = 0
        while index < len(rdata):
            size = rdata[index]
            index += 1
            parts.append(rdata[index:index + size].decode("utf-8", "replace"))
            index += size
        text = "".join(parts).strip()
        if text:
            texts.append(text)
    return flags & 0x000F, texts


def ask(server, query):
    transaction, message = build_query(query)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(message, (server, 53))
        packet, _ = sock.recvfrom(4096)
    return parse_txt(packet, transaction)


def lookup_txt(query):
    servers = dns_servers()
    if not servers:
        raise OSError("No DNS server is configured")
    errors = []
    for server in servers:
        try:
            rcode, texts = ask(server, query)
        except OSError as exc:
            errors.append(f"{server}: {exc}")
            continue
        if rcode in (0, 3):
            return texts
        errors.append(f"{server}: DNS rcode {rcode}")
    raise OSError("; ".join(errors) or "DNS lookup failed")


def paint(text, color):
    if not sys.stdout.isatty():
        return text
    codes = {"green": "32", "red": "31", "yellow": "33"}
    return f"\033[{codes[color]}m{text}\033[0m"


def main(argv):
    if len(argv) > 1:
        raw = argv[1]
    else:
        raw = input("Enter the full domain name (example: example.com): ")
        if not sys.stdin.isatty():
            print()
    try:
        display, query = dmarc_query(raw)
        texts = lookup_txt(query)
    except ValueError as exc:
        print(paint(str(exc), "yellow"))
        return 2
    except OSError as exc:
        label = clean_text(raw, "domain")
        print(paint(f"{label} : LOOKUP FAILED: {exc}", "red"))
        return 2

    dmarc = [text for text in texts if text.lower().lstrip().startswith("v=dmarc1")]
    if not texts:
        print(paint(f"{display} : DMARC MISSING", "red"))
        return 1
    if not dmarc:
        print(paint(f"{display} : TXT FOUND, NOT A DMARC RECORD", "yellow"))
        for text in texts:
            print(f"  {text}")
        return 1
    print(paint(f"{display} : DMARC FOUND", "green"))
    for text in dmarc:
        print(f"  {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
