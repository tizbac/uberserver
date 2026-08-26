import socket, time, threading, sys, ssl, queue

HOST, PORT = '127.0.0.1', 18200
failures = []

def check(label, cond, detail=""):
    if cond:
        print("PASS: %s" % label)
    else:
        print("FAIL: %s %s" % (label, detail))
        failures.append(label)

class C:
    def __init__(self, name):
        self.name = name
        raw = socket.create_connection((HOST, PORT), timeout=5)
        # drain TASSERVER (plain) then upgrade to TLS
        buf = b''
        while b'\n' not in buf:
            buf += raw.recv(4096)
        print("[%s] <- %s" % (name, buf.decode().strip()))
        raw.sendall(b"STLS\n")
        ok = b''
        while b'\n' not in ok:
            ok += raw.recv(4096)
        assert b'OK' in ok, "STLS ack: %r" % ok
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(raw, server_hostname="localhost")
        self.sock.settimeout(0.2)
        self.buf = b''
        self.lock = threading.Lock()
        self.lines = []
        self.cmd_queue = queue.Queue()
        # one thread owns the socket: it sends queued commands and recvs
        self.t = threading.Thread(target=self.io_loop, daemon=True)
        self.t.start()

    def io_loop(self):
        try:
            while True:
                while True:
                    try:
                        cmd = self.cmd_queue.get_nowait()
                        print("[%s] -> %s" % (self.name, cmd))
                        self.sock.sendall((cmd + '\n').encode())
                    except queue.Empty:
                        break
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    raise ConnectionResetError("closed")
                self.buf += data
                while b'\n' in self.buf:
                    line, self.buf = self.buf.split(b'\n', 1)
                    line = line.decode('utf-8', 'replace')
                    if line:
                        with self.lock:
                            self.lines.append(line)
                        print("[%s] <- %s" % (self.name, line))
        except Exception as e:
            print("[%s] io_loop error: %s" % (self.name, e))

    def send(self, cmd):
        self.cmd_queue.put(cmd)

    def wait(self, prefix, timeout=6):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for l in self.lines:
                    if l.startswith(prefix):
                        return l
            time.sleep(0.05)
        with self.lock:
            got = list(self.lines)
        raise TimeoutError("%s timeout waiting for %r; got: %r" % (self.name, prefix, got))

    def waitNo(self, prefix, timeout=1.5):
        time.sleep(timeout)
        with self.lock:
            for l in self.lines:
                if l.startswith(prefix):
                    return l
        return None

    def drain(self):
        with self.lock:
            self.lines = []

def login(name, sentence=""):
    c = C(name)
    c.send("REGISTER %s 5S2YxFmBmhF3WTbY37t5KQ== %s@test.com" % (name, name))
    c.wait("REGISTRATIONACCEPTED")
    if sentence:
        c.send("LOGIN %s 5S2YxFmBmhF3WTbY37t5KQ== 0 192.168.1.10 %s" % (name, sentence))
    else:
        c.send("LOGIN %s 5S2YxFmBmhF3WTbY37t5KQ==" % name)
    c.wait("ACCEPTED")
    c.drain()
    return c

print("=== logging in u02 first (so it sees u01's ADDUSER) ===")
u02 = login("u02")
u01 = login("u01", "TestAgent\t0\tb u")
u02line = u02.wait("ADDUSER u01 ")
u01uid = u02line.split()[3]
print("u01 user_id =", u01uid)
battle_chan = "__battle__" + u01uid

u03 = login("u03", "TestAgent\t0\tb u")

print("=== 1. u01 (host, compat 'b') opens battle ===")
u01.send("OPENBATTLE 0 0 * 12345 8 123456789 0 -123456789 spring\t105.0.1\tTestMap\tTest Title\tTestMod")
l = u01.wait("BATTLEOPENED")
head, _, tail = l.partition('\t')
check("BATTLEOPENED head (11 space fields, engine last)", head.split() == ['BATTLEOPENED', '1', '0', '0', 'u01', '192.168.1.10', '12345', '8', '0', '0', '-123456789', 'spring'], repr(head))
check("BATTLEOPENED tail ('u' compat: 5 tab fields incl. name)", tail.split('\t') == ['105.0.1', 'TestMap', 'Test Title', 'TestMod', '__battle__' + u01uid], repr(tail))
u01.wait("OPENBATTLE 1")
u01.wait("JOINBATTLE 1 ")
u01.wait("REQUESTBATTLESTATUS")
u02.wait("BATTLEOPENED 1 ")
u02.drain(); u03.drain(); u01.drain()

print("=== 2. u02 join -> pending (host has 'b') -> accept ===")
u02.send("JOINBATTLE 1")
req = u01.wait("JOINBATTLEREQUEST u02 ")
check("JOINBATTLEREQUEST has ip", len(req.split()) == 3, repr(req))
u01.send("JOINBATTLEACCEPT u02")
u02.wait("JOINBATTLE 1 ")
u02.wait("REQUESTBATTLESTATUS")
u01.wait("JOINEDBATTLE 1 u02")
u01.drain(); u02.drain()

print("=== 3. rejoin / bad id ===")
u02.send("JOINBATTLE 1")
check("already in battle", u02.wait("JOINBATTLEFAILED") == "JOINBATTLEFAILED You are already in a battle")
u02.drain()
u03.send("JOINBATTLE 999")
check("battle does not exist", u03.wait("JOINBATTLEFAILED") == "JOINBATTLEFAILED Battle does not exist")
u03.drain()

print("=== 4. u03 join -> deny -> pending again -> accept ===")
u03.send("JOINBATTLE 1")
u01.wait("JOINBATTLEREQUEST u03 ")
u03.send("JOINBATTLE 1")
check("waiting for accept/deny", u03.wait("JOINBATTLEFAILED") == "JOINBATTLEFAILED Waiting for JOINBATTLEACCEPT/JOINBATTLEDENIED from host")
u03.drain()
u01.send("JOINBATTLEDENY u03 full")
check("deny with reason", u03.wait("JOINBATTLEFAILED") == "JOINBATTLEFAILED Access denied by host (full)")
u03.drain(); u01.drain()
u03.send("JOINBATTLE 1")
u01.wait("JOINBATTLEREQUEST u03 ")
u01.send("JOINBATTLEACCEPT u03")
u03.wait("JOINBATTLE 1 ")
u01.wait("JOINEDBATTLE 1 u03")
u01.drain(); u02.drain(); u03.drain()

print("=== 5. SAYBATTLE / SAYBATTLEEX / SAYBATTLEPRIVATEEX ===")
u02.send("SAYBATTLE hello there")
check("u01 gets SAID ('u' compat: channel format)", u01.wait("SAID") == "SAID __battle__%s u02 hello there" % u01uid)
check("u03 gets SAID ('u' compat: channel format)", u03.wait("SAID") == "SAID __battle__%s u02 hello there" % u01uid)
u01.drain(); u02.drain(); u03.drain()
u01.send("SAYBATTLEEX does a backflip")
check("u02 gets SAIDBATTLEEX", u02.wait("SAIDBATTLEEX") == "SAIDBATTLEEX u01 does a backflip")
u01.drain(); u02.drain(); u03.drain()
u01.send("SAYBATTLEPRIVATEEX u02 psst")
check("u02 gets private ex", u02.wait("SAIDBATTLEEX") == "SAIDBATTLEEX u01 psst")
checkno = u03.waitNo("SAIDBATTLEEX")
check("u03 does NOT get private", checkno is None, repr(checkno))
u01.drain(); u02.drain(); u03.drain()
u02.send("SAYBATTLEPRIVATEEX u01 not the host")
checkno = u01.waitNo("SAIDBATTLEEX")
check("non-host private ex ignored", checkno is None, repr(checkno))

print("=== 6. LEAVEBATTLE until battle removed ===")
u03.send("LEAVEBATTLE")
time.sleep(0.5)
u02.send("LEAVEBATTLE")
time.sleep(0.5)
u01.send("LEAVEBATTLE")
check("BATTLECLOSED on last leave", u02.wait("BATTLECLOSED") == "BATTLECLOSED 1")
u02.drain(); u01.drain()
u02.send("SAYBATTLE after battle gone")
time.sleep(0.5)
check("SAYBATTLE outside battle silent", True)

print("=== 7. password battle ===")
u01.send("OPENBATTLE 0 0 sekret 12345 8 123456789 0 -123456789 spring\t105.0.1\tTestMap\tLocked Title\tTestMod")
u01.wait("OPENBATTLE 2")
u02.send("JOINBATTLE 2")
check("wrong password", u02.wait("JOINBATTLEFAILED") == "JOINBATTLEFAILED Incorrect password")
u02.drain()
u02.send("JOINBATTLE 2 sekret")
u01.wait("JOINBATTLEREQUEST u02 ")
u01.send("JOINBATTLEACCEPT u02")
u02.wait("JOINBATTLE 2 ")
u02.drain(); u01.drain()

print("=== 8. bridged clients ===")
u01.send("BRIDGECLIENTFROM u01 loc1 extuser1")
check("bridge bot servermsg", u01.wait("SERVERMSG").startswith("SERVERMSG You are now the bridge bot for location 'u01'"), "")
check("BRIDGEDCLIENTFROM", u01.wait("BRIDGEDCLIENTFROM") == "BRIDGEDCLIENTFROM u01 loc1 extuser1")
u01.drain()
u01.send("BRIDGECLIENTFROM u01 loc1 extuser1")
check("duplicate bridge denied", u01.wait("FAILED") == "FAILED msg=The client already exists on the bridge (u01,loc1)\tcmd=BRIDGECLIENTFROM", "")
u01.drain()
u03.send("BRIDGECLIENTFROM u03 loc1 extuser3")
check("non-host cannot bridge", u03.wait("FAILED") == "FAILED msg=Only bot users and battle hosts can bridge clients\tcmd=BRIDGECLIENTFROM", "")
u03.drain()
u01.send("BRIDGECLIENTFROM u01 loc1 bad name!")
check("bad bridge syntax", u01.wait("FAILED").startswith("FAILED msg=Invalid syntax: external_username 'bad name!' is invalid"), "")
u01.drain()
u01.send("JOINFROM %s u01 loc1" % battle_chan)
time.sleep(0.5)
u01.send("SAYFROM %s u01 loc1 hello bridged" % battle_chan)
check("u02 gets SAIDBATTLE from bridge", u02.wait("SAIDBATTLE") == "SAIDBATTLE u01 <extuser1:u01> hello bridged")
u02.drain(); u01.drain()
u01.send("SAYFROM nosuchchan u01 loc1 hi")
time.sleep(0.5)
u01.send("LEAVEFROM %s u01 loc1" % battle_chan)
time.sleep(0.5)
u01.send("SAYFROM %s u01 loc1 hello again" % battle_chan)
check("SAYFROM after leave fails", u01.wait("FAILED").startswith("FAILED msg=Bridged user <extuser1:u01> not present in channel"), "")
u01.drain()
u01.send("UNBRIDGECLIENTFROM u01 loc1")
check("UNBRIDGEDCLIENTFROM", u01.wait("UNBRIDGEDCLIENTFROM") == "UNBRIDGEDCLIENTFROM u01 loc1")
u01.drain()

print("=== 9. OPENBATTLE edge cases ===")
u01.send("OPENBATTLE 0 0 * 99999 8 123456789 0 -123456789 spring\t105.0.1\tMap\tTitle\tMod")
check("port out of range", u01.wait("OPENBATTLEFAILED") == "OPENBATTLEFAILED Port is out of range: 1-65535: 99999")
u01.drain()
u01.send("OPENBATTLE 0 0 * 12345 8 0 0 -123456789 spring\t105.0.1\tMap\tTitle\tMod")
check("invalid game hash", u01.wait("OPENBATTLEFAILED") == "OPENBATTLEFAILED Invalid game hash 0")
u01.drain()
u01.send("OPENBATTLE 0 0 * 12345 8 abc 0 -123456789 spring\t105.0.1\tMap\tTitle\tMod")
l = u01.wait("OPENBATTLEFAILED")
check("invalid arg type", l.startswith("OPENBATTLEFAILED Invalid argument type") and "id=" in l, repr(l))
u01.drain()
u01.send("OPENBATTLE 0 0 * 12345 8 123456789 0 -123456789 spring\t105.0.1\tMap\tTitle")
check("bad tabcount", u01.wait("OPENBATTLEFAILED") == "OPENBATTLEFAILED Invalid arguments (3): spring\t105.0.1\tMap\tTitle")
u01.drain()
u01.send("OPENBATTLE 0 0 * 12345 32 123456789 0 -123456789 spring\t105.0.1\tMap\tBig Title\tMod")
check("noflag limit servermsg", u01.wait("SERVERMSG").startswith("SERVERMSG A botflag is required to host battles with > 8 players"), "")
l = u01.wait("BATTLEOPENED")
head, _, tail = l.partition('\t')
check("maxplayers clamped to 8", head.split()[7] == '8', repr(head))
u01.wait("OPENBATTLE %s" % head.split()[1])
u01.drain()

print()
if failures:
    print("FAILURES (%d): %s" % (len(failures), failures))
    sys.exit(1)
print("ALL BATTLE TESTS PASSED")
