#!/usr/bin/env python3
"""TLS transport tests: STLS (the real SpringLobby flow: plaintext OK ack,
then handshake, then TASSERVER banner over TLS) and the legacy STARTTLS flow."""
import socket, ssl

HOST, PORT = "127.0.0.1", 18200

def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def read_line(s):
    buf = b''
    while b'\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise AssertionError("connection closed")
        buf += chunk
    return buf.split(b'\n', 1)[0].decode()

def auth(s, name):
    s.sendall(("REGISTER %s 5S2YxFmBmhF3WTbY37t5KQ== %s@test.com\n" % (name, name)).encode())
    line = read_line(s)
    assert "REGISTRATIONACCEPTED" in line, line
    s.sendall(("LOGIN %s 5S2YxFmBmhF3WTbY37t5KQ==\n" % name).encode())
    line = read_line(s)
    assert "ACCEPTED" in line, line

def stls_flow():
    raw = socket.create_connection((HOST, PORT), timeout=5)
    banner = read_line(raw)
    assert banner.startswith("TASSERVER"), banner
    raw.sendall(b"STLS\n")
    ok = read_line(raw)
    assert ok == "OK cmd=STLS", ok
    s = ctx().wrap_socket(raw, server_hostname="localhost")
    banner2 = read_line(s)
    assert banner2.startswith("TASSERVER"), banner2
    auth(s, "tlu1")
    s.close()
    print("ok: STLS flow (plaintext OK ack, TLS banner, auth over TLS)")

def starttls_flow():
    raw = socket.create_connection((HOST, PORT), timeout=5)
    banner = read_line(raw)
    assert banner.startswith("TASSERVER"), banner
    raw.sendall(b"STARTTLS\n")
    s = ctx().wrap_socket(raw, server_hostname="localhost")
    banner2 = read_line(s)
    assert banner2.startswith("TASSERVER"), banner2
    auth(s, "tlu2")
    s.close()
    print("ok: STARTTLS flow (TLS banner, auth over TLS)")

stls_flow()
starttls_flow()
print("test_tls: all checks passed")
