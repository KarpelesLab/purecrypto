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
"""
import select
import socket
import sys

listen_port, target_port, percent = (int(a) for a in sys.argv[1:4])
state = int(sys.argv[4]) if len(sys.argv) > 4 else 1


def coin() -> bool:
    """True with probability PERCENT/100, from the LCG (Numerical Recipes)."""
    global state
    state = (state * 1664525 + 1013904223) % (1 << 32)
    return (state >> 16) % 100 < percent


front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("127.0.0.1", listen_port))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
back.connect(("127.0.0.1", target_port))
client = None
counts = {"c->s": 0, "s->c": 0}
while True:
    ready, _, _ = select.select([front, back], [], [])
    for sock in ready:
        if sock is front:
            data, client = front.recvfrom(65535)
            direction = "c->s"
        else:
            data = back.recv(65535)
            direction = "s->c"
        counts[direction] += 1
        if coin():
            print(f"drop {direction} #{counts[direction]} ({len(data)} bytes)", file=sys.stderr, flush=True)
            continue
        if direction == "c->s":
            back.send(data)
        elif client is not None:
            front.sendto(data, client)
