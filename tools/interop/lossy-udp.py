#!/usr/bin/env python3
"""A lossy UDP relay for the DTLS `loss` cases.

usage: lossy-udp.py LISTEN_PORT TARGET_PORT PERCENT [SEED]

Forwards datagrams between the one client that talks to LISTEN_PORT and the
server on 127.0.0.1:TARGET_PORT, dropping PERCENT of them in each direction.
The choice is pseudo-random from a fixed SEED (default 1) — a linear
congruential generator, so a failing run reproduces exactly and no flight is
hit by a periodic pattern it can never get past. With the handshake flights
of both sides spanning several datagrams, fragments of every flight are
lost, which forces the retransmission machinery on both ends: ACK-driven
(RFC 9147 §7) on DTLS 1.3, timer-driven whole flights (RFC 6347 §4.2.4) on
DTLS 1.2. Each dropped datagram is logged to stderr.

Two environment variables turn the relay into a debugging tool:

  LOSSY_DROP   a comma-separated list of datagrams to drop on top of the
               random ones (use PERCENT 0 for only these): `c->s#4` is the
               4th datagram from the client, `s->c#2-5` the server's 2nd to
               5th, `c->s@e2#1` the client's 1st datagram with a record in
               epoch 2 (the DTLS 1.3 handshake epoch: an ACK or the
               client's final flight), `c->s@e2>=60#1` the 1st such
               datagram of at least 60 bytes (the Finished, not an ACK),
               `s->c@e2~3000` every datagram of the server with a record
               in epoch 2 during the 3000 ms that follow the first one
               (a flight and its first retransmissions, however many
               datagrams the peer needs for them).
  LOSSY_TRACE  when set (to anything but 0), every datagram is logged to
               stderr with a millisecond timestamp and the header of each
               record it can walk: content type (or `enc` for a DTLS 1.3
               unified header, whose type is encrypted), epoch, length.
"""
import os
import re
import select
import socket
import sys
import time

listen_port, target_port, percent = (int(a) for a in sys.argv[1:4])
state = int(sys.argv[4]) if len(sys.argv) > 4 else 1
trace = os.environ.get("LOSSY_TRACE", "0") not in ("", "0")

TYPES = {20: "ccs", 21: "alert", 22: "handshake", 23: "appdata", 26: "ack"}
HANDSHAKE = {
    1: "ClientHello", 2: "ServerHello", 3: "HelloVerifyRequest",
    4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate",
    12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
    15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished",
}


def records(data: bytes):
    """The records of a datagram as (label, epoch, length); stops at the
    first one it cannot walk (a unified header without a length field
    takes the rest of the datagram)."""
    out = []
    off = 0
    while off < len(data):
        first = data[off]
        if first & 0xE0 == 0x20:
            # RFC 9147 §4: 0 0 1 C S L E E.
            hdr = 1 + (8 if first & 0x10 else 0) + (2 if first & 0x08 else 1)
            if first & 0x04:
                if off + hdr + 2 > len(data):
                    break
                length = int.from_bytes(data[off + hdr:off + hdr + 2], "big")
                hdr += 2
            else:
                length = len(data) - off - hdr
            out.append(("enc", first & 0x03, length))
            off += hdr + length
        elif first in TYPES and off + 13 <= len(data):
            epoch = int.from_bytes(data[off + 3:off + 5], "big")
            length = int.from_bytes(data[off + 11:off + 13], "big")
            label = TYPES[first]
            if first == 22 and epoch == 0 and off + 25 <= len(data):
                # Plaintext handshake: message type, message_seq and the
                # fragment's place in the message.
                body = data[off + 13:]
                name = HANDSHAKE.get(body[0], str(body[0]))
                total = int.from_bytes(body[1:4], "big")
                msg_seq = int.from_bytes(body[4:6], "big")
                frag_off = int.from_bytes(body[6:9], "big")
                frag_len = int.from_bytes(body[9:12], "big")
                label = f"{name}[seq {msg_seq}, {frag_off}+{frag_len}/{total}]"
            out.append((label, epoch, length))
            off += 13 + length
        else:
            break
    return out


def parse_rules(spec: str):
    """LOSSY_DROP as a list of (direction, epoch or None, min size, first,
    last, window in seconds or None)."""
    rules = []
    for item in filter(None, (s.strip() for s in spec.split(","))):
        m = re.fullmatch(
            r"(c->s|s->c)(?:@e(\d+))?(?:>=(\d+))?(?:#(\d+)(?:-(\d+))?|~(\d+))", item)
        if not m:
            sys.exit(f"lossy-udp: bad LOSSY_DROP entry {item!r}")
        direction, epoch, size, first, last, window = m.groups()
        rules.append((
            direction,
            None if epoch is None else int(epoch),
            int(size or 0),
            int(first or 0),
            int(last or first or 0),
            None if window is None else int(window) / 1000,
        ))
    return rules


rules = parse_rules(os.environ.get("LOSSY_DROP", ""))
# Per rule: how many datagrams matching its direction / epoch / size went
# by, and when the first one did.
rule_counts = [0] * len(rules)
rule_first = [None] * len(rules)


def coin() -> bool:
    """True with probability PERCENT/100, from the LCG (Numerical Recipes)."""
    global state
    state = (state * 1664525 + 1013904223) % (1 << 32)
    return (state >> 16) % 100 < percent


def targeted(direction: str, data: bytes, recs) -> bool:
    hit = False
    now = time.monotonic()
    for i, (rdir, epoch, size, first, last, window) in enumerate(rules):
        if rdir != direction or len(data) < size:
            continue
        if epoch is not None and all(rec[1] != epoch for rec in recs):
            continue
        rule_counts[i] += 1
        if rule_first[i] is None:
            rule_first[i] = now
        if window is not None:
            hit = hit or now - rule_first[i] <= window
        elif first <= rule_counts[i] <= last:
            hit = True
    return hit


front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("127.0.0.1", listen_port))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
back.connect(("127.0.0.1", target_port))
client = None
counts = {"c->s": 0, "s->c": 0}
start = time.monotonic()
while True:
    ready, _, _ = select.select([front, back], [], [])
    for sock in ready:
        try:
            if sock is front:
                data, client = front.recvfrom(65535)
                direction = "c->s"
            else:
                data = back.recv(65535)
                direction = "s->c"
        except ConnectionError:
            # An ICMP port-unreachable for a datagram relayed to a server
            # that has gone: nothing to forward.
            continue
        counts[direction] += 1
        recs = records(data) if (trace or rules) else []
        # The coin is tossed for every datagram, targeted or not, so the
        # random pattern of a SEED does not depend on LOSSY_DROP.
        drop = coin()
        drop = targeted(direction, data, recs) or drop
        if trace:
            what = " ".join(f"{label}/e{epoch}/{length}" for label, epoch, length in recs)
            ms = int((time.monotonic() - start) * 1000)
            verb = "drop" if drop else "pass"
            print(f"{ms:6d} {verb} {direction} #{counts[direction]} ({len(data)} bytes) {what}",
                  file=sys.stderr, flush=True)
        elif drop:
            print(f"drop {direction} #{counts[direction]} ({len(data)} bytes)", file=sys.stderr, flush=True)
        if drop:
            continue
        try:
            if direction == "c->s":
                back.send(data)
            elif client is not None:
                front.sendto(data, client)
        except ConnectionError:
            pass
