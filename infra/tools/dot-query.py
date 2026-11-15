#!/usr/bin/env python3
"""Interroge un résolveur DNS-over-TLS comme le fait le « DNS privé » d'Android (diagnostic).

  python3 tools/dot-query.py dns.exemple.fr app-measurement.com
  python3 tools/dot-query.py --connect 127.0.0.1 --cafile data/caddy/server-root-ca.crt dns.vigie.lan example.org

Affiche le certificat présenté (sujet, émetteur, empreinte SHA-256), le code de réponse et les
adresses A/AAAA. Un domaine bloqué par AdGuard Home répond 0.0.0.0 / ::. Python 3 standard.
"""
import argparse
import hashlib
import secrets
import socket
import ssl
import struct
import sys


def build_query(name, qtype):
    qid = secrets.randbits(16)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\0"
    return qid, header + q + struct.pack(">HH", qtype, 1)


def skip_name(buf, off):
    while True:
        n = buf[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += n + 1


def parse_answers(buf):
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        off = skip_name(buf, off) + 4
    out = []
    for _ in range(an):
        off = skip_name(buf, off)
        typ, _, _, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + rdlen]
        off += rdlen
        if typ == 1:
            out.append(socket.inet_ntop(socket.AF_INET, rd))
        elif typ == 28:
            out.append(socket.inet_ntop(socket.AF_INET6, rd))
    rcode = flags & 0xF
    return {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(rcode, str(rcode)), out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("server", help="nom d'hôte DoT (SNI et vérification du certificat)")
    ap.add_argument("name", help="nom à résoudre")
    ap.add_argument("--connect", help="adresse IP à joindre (défaut : résolution de server)")
    ap.add_argument("--port", type=int, default=853)
    ap.add_argument("--cafile", help="AC à utiliser (mode TLS interne)")
    ap.add_argument("--type", default="A", choices=["A", "AAAA"])
    a = ap.parse_args()

    ctx = ssl.create_default_context(cafile=a.cafile)
    with socket.create_connection((a.connect or a.server, a.port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=a.server) as s:
            der = s.getpeercert(binary_form=True)
            cert = s.getpeercert()
            subj = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            print(f"TLS {s.version()} ; certificat : CN={subj.get('commonName', '')} "
                  f"SAN={[v for k, v in cert.get('subjectAltName', ())]}")
            print(f"  émetteur : {issuer.get('commonName', '')} ; expire : {cert.get('notAfter')}")
            print(f"  SHA-256 : {hashlib.sha256(der).hexdigest()}")
            qid, q = build_query(a.name, 1 if a.type == "A" else 28)
            s.sendall(struct.pack(">H", len(q)) + q)
            ln = struct.unpack(">H", s.recv(2))[0]
            buf = b""
            while len(buf) < ln:
                chunk = s.recv(ln - len(buf))
                if not chunk:
                    break
                buf += chunk
    rcode, addrs = parse_answers(buf)
    print(f"{a.name} {a.type} : {rcode} {' '.join(addrs)}")
    blocked = any(x in ("0.0.0.0", "::") for x in addrs)
    print("=> BLOQUÉ par le filtrage" if blocked else "=> non bloqué")
    return 0


if __name__ == "__main__":
    sys.exit(main())
