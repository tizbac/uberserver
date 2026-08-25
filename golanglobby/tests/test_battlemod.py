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
        buf = b''
        while b'\n' not in buf:
            buf += raw.recv(4096)
        raw.sendall(b"STARTTLS\n")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(raw, server_hostname="localhost")
        self.sock.settimeout(0.2)
        self.buf = b''
        self.lock = threading.Lock()
        self.lines = []
        self.cmd_queue = queue.Queue()
        self.t = threading.Thread(target=self.io_loop, daemon=True)
        self.t.start()

    def io_loop(self):
        try:
            while True:
                while True:
                    try:
                        cmd = self.cmd_queue.get_nowait()
                        self.sock.sendall((cmd + '\n').encode())
                    except queue.Empty:
                        break
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    print("[%s] <- CLOSED" % self.name)
                    return
                self.buf += data
                while b'\n' in self.buf:
                    line, self.buf = self.buf.split(b'\n', 1)
                    line = line.decode('utf-8', 'replace')
                    if line:
                        with self.lock:
                            self.lines.append(line)
        except Exception as e:
            print("[%s] io_loop error: %s" % (self.name, e))

    def send(self, cmd):
        self.cmd_queue.put(cmd)

    def wait(self, prefix, timeout=6):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for i, l in enumerate(self.lines):
                    if l.startswith(prefix):
                        del self.lines[i]
                        return l
            time.sleep(0.05)
        with self.lock:
            got = list(self.lines)
        raise TimeoutError("%s timeout waiting for %r; got: %r" % (self.name, prefix, got))

    def waitNo(self, prefix, timeout=1.0):
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

print("=== setup ===")
o1 = login("o01")
h1 = login("hst", "TestAgent\t0\tb u")
line = o1.wait("ADDUSER hst ")
h1uid = line.split()[3]
print("h1 user_id =", h1uid)
bchan = "__battle__" + h1uid
m1 = login("mmb", "TestAgent\t0\tb u")
m2 = login("mm2", "TestAgent\t0\tb")
admin = C("admin")
admin.send("LOGIN admin 6oR5iLpZcn2/TjTudXJtww==")
admin.wait("ACCEPTED")
admin.drain()
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print("=== 1. open battle + 3 players ===")
h1.send("OPENBATTLE 0 0 * 12345 8 123456789 0 -123456789 spring\t105.0.1\tTestMap\tModTitle\tTestMod")
h1.wait("BATTLEOPENED")
h1.wait("OPENBATTLE 1")
h1.wait("JOINBATTLE 1 ")
h1.wait("REQUESTBATTLESTATUS")
h1.drain()
for u in (m1, m2):
    u.send("JOINBATTLE 1")
    h1.wait("JOINBATTLEREQUEST %s " % u.name)
    h1.send("JOINBATTLEACCEPT %s" % u.name)
    u.wait("JOINBATTLE 1 ")
    h1.wait("JOINEDBATTLE 1 %s" % u.name)
o1.drain(); h1.drain(); m1.drain(); m2.drain(); admin.drain()

# status bitfield: side<<24 | sync<<22 | handicap<<11 | mode<<10 | ally<<6 | id<<2 | ready<<1
STATUS_A = (1 << 24) | (1 << 10)  # side=1 mode=1 -> 16778240

print("=== 2. MYBATTLESTATUS ===")
m1.send("MYBATTLESTATUS %d 12" % STATUS_A)
check("updatebattleinfo specs 0->2", h1.wait("UPDATEBATTLEINFO") == "UPDATEBATTLEINFO 1 2 0 -123456789 TestMap")
check("clientbattlestatus broadcast", h1.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % STATUS_A)
check("member sees status", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % STATUS_A)
o1.drain(); h1.drain(); m1.drain(); m2.drain()

m1.send("MYBATTLESTATUS %d 12" % STATUS_A)
check("unchanged -> self only", m1.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % STATUS_A)
check("host does NOT see repeat", h1.waitNo("CLIENTBATTLESTATUS") is None, "unexpected")
check("member does NOT see repeat", m2.waitNo("CLIENTBATTLESTATUS") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print("=== 3. FORCETEAMCOLOR / HANDICAP / FORCETEAMNO / FORCEALLYNO ===")
h1.send("FORCETEAMCOLOR mmb 99")
check("forced color broadcast (raw string)", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 99" % STATUS_A)
o1.drain(); h1.drain(); m1.drain(); m2.drain()

# int 12 != str "99" in Python -> broadcast again
m1.send("MYBATTLESTATUS %d 12" % STATUS_A)
check("str/int color mismatch re-broadcasts", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % STATUS_A)
o1.drain(); h1.drain(); m1.drain(); m2.drain()

S_HAND = STATUS_A | (25 << 11)
h1.send("HANDICAP mmb 25")
check("handicap 25", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % S_HAND)
o1.drain(); h1.drain(); m1.drain(); m2.drain()
h1.send("HANDICAP mmb 101")
check("handicap 101 rejected", m2.waitNo("CLIENTBATTLESTATUS") is None, "unexpected")
h1.send("HANDICAP mmb abc")
check("handicap abc rejected", m2.waitNo("CLIENTBATTLESTATUS") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

S_ID = S_HAND | (3 << 2)
h1.send("FORCETEAMNO mmb 3")
check("forceteamno 3", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % S_ID)
o1.drain(); h1.drain(); m1.drain(); m2.drain()

S_ALLY = S_ID | (5 << 6)
h1.send("FORCEALLYNO mmb 5")
check("forceallyno 5", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % S_ALLY)
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print("=== 4. FORCESPECTATORMODE ===")
S_SPEC = S_ALLY & ~(1 << 10)
h1.send("FORCESPECTATORMODE mmb")
check("forced spec status", m2.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % S_SPEC)
check("forced spec updatebattleinfo 2->3", h1.wait("UPDATEBATTLEINFO") == "UPDATEBATTLEINFO 1 3 0 -123456789 TestMap")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
h1.send("FORCESPECTATORMODE mmb")
check("already spectating -> nothing", m2.waitNo("CLIENTBATTLESTATUS") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print("=== 5. BATTLEHOSTMSG ===")
h1.send("BATTLEHOSTMSG %s mmb hello mmb" % bchan)
check("hostmsg to 'u' compat user -> SAIDEX", m1.wait("SAIDEX") == "SAIDEX %s hst hello mmb" % bchan)
h1.send("BATTLEHOSTMSG %s mm2 hello mm2" % bchan)
check("hostmsg to non-'u' user -> SAIDBATTLEEX", m2.wait("SAIDBATTLEEX") == "SAIDBATTLEEX hst hello mm2")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
m1.send("BATTLEHOSTMSG %s mm2 not the host" % bchan)
check("non-host hostmsg ignored", m2.waitNo("SAIDBATTLEEX") is None, "unexpected")
h1.send("BATTLEHOSTMSG __battle__999 m1 wrong battle")
check("wrong battle name ignored", m1.waitNo("SAIDEX") is None, "unexpected")
h1.send("BATTLEHOSTMSG %s o01 outsider" % bchan)
check("non-member ignored", o1.waitNo("SAIDBATTLEEX") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print("=== 6. RING ===")
h1.send("RING mmb")
check("host rings member", m1.wait("RING") == "RING hst")
m1.send("RING hst")
check("member rings host", h1.wait("RING") == "RING mmb")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
m1.send("RING mm2")
check("member rings member (not host) ignored", m2.waitNo("RING") is None, "unexpected")
o1.send("RING hst")
check("no-battle ringer ignored", h1.waitNo("RING") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
admin.send("JOINBATTLE 1")
admin.wait("JOINBATTLE 1 ")
h1.wait("JOINEDBATTLE 1 admin")
h1.drain(); admin.drain()
admin.send("RING o01")
check("mod rings outsider", o1.wait("RING") == "RING admin")
admin.send("LEAVEBATTLE")
h1.wait("LEFTBATTLE 1 admin")
o1.drain(); h1.drain(); m1.drain(); m2.drain(); admin.drain()

print("=== 7. KICKFROMBATTLE ===")
m1.send("KICKFROMBATTLE mm2")
check("non-host kick ignored", m2.waitNo("FORCEQUITBATTLE") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
h1.send("KICKFROMBATTLE mm2")
check("kick -> FORCEQUITBATTLE", m2.wait("FORCEQUITBATTLE") == "FORCEQUITBATTLE hst")
check("kick -> LEFTBATTLE", h1.wait("LEFTBATTLE 1 mm2") == "LEFTBATTLE 1 mm2")
check("kick -> specs 3->2", m1.wait("UPDATEBATTLEINFO") == "UPDATEBATTLEINFO 1 2 0 -123456789 TestMap")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

admin.send("SETACCESS mmb mod")
admin.wait("OK cmd=SETACCESS")
check("m1 now mod", admin.wait("CLIENTSTATUS") == "CLIENTSTATUS mmb 32")
o1.drain(); h1.drain(); m1.drain(); admin.drain()
h1.send("KICKFROMBATTLE m1")
check("mod cannot be kicked", m1.waitNo("FORCEQUITBATTLE") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); admin.drain()
admin.send("SETACCESS mmb user")
admin.wait("OK cmd=SETACCESS")
admin.wait("CLIENTSTATUS mmb 0")
o1.drain(); h1.drain(); m1.drain(); admin.drain()

print("=== 8. SETSCRIPTTAGS / REMOVESCRIPTTAGS ===")
h1.send("SETSCRIPTTAGS Tag1=val1\tTAG2=val2")
check("set tags (lowercased keys, tab-joined)", m1.wait("SETSCRIPTTAGS") == "SETSCRIPTTAGS tag1=val1\ttag2=val2")
h1.send("SETSCRIPTTAGS tag1=newval")
check("set tags merge (update)", m1.wait("SETSCRIPTTAGS") == "SETSCRIPTTAGS tag1=newval")
m1.send("SETSCRIPTTAGS x=1")
check("non-host set tags -> FAILED", m1.wait("FAILED") == "FAILED msg=You are not allowed to change settings in this battle\tcmd=SETSCRIPTTAGS")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
h1.send("REMOVESCRIPTTAGS tag2 TAG2 missing")
check("remove tags (dedup, existing only)", m1.wait("REMOVESCRIPTTAGS") == "REMOVESCRIPTTAGS TAG2")
h1.send("REMOVESCRIPTTAGS missing")
check("remove nothing -> silent", m1.waitNo("REMOVESCRIPTTAGS") is None, "unexpected")
m1.send("REMOVESCRIPTTAGS tag1")
check("non-host remove tags -> FAILED", m1.wait("FAILED") == "FAILED msg=You are not allowed to change settings in this battle\tcmd=REMOVESCRIPTTAGS")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
o1.send("SETSCRIPTTAGS x=1")
check("outside battle set tags -> FAILED", o1.wait("FAILED") == "FAILED msg=You are not allowed to change settings in this battle\tcmd=SETSCRIPTTAGS")
o1.drain(); h1.drain(); m1.drain()

print("=== 9. UPDATEBATTLEINFO ===")
h1.send("UPDATEBATTLEINFO 0 1 123456789 NewMap")
check("update battle info broadcast", m1.wait("UPDATEBATTLEINFO") == "UPDATEBATTLEINFO 1 2 1 123456789 NewMap")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
m1.send("UPDATEBATTLEINFO 0 1 123456789 OtherMap")
check("non-host update ignored", m1.waitNo("UPDATEBATTLEINFO") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain()
h1.send("UPDATEBATTLEINFO 0 1 abc Map2")
check("bad maphash (trailing space)", h1.wait("SERVERMSG") == "SERVERMSG UPDATEBATTLEINFO failed - Invalid map hash send: Map2 abc ")
h1.send("UPDATEBATTLEINFO 0 1 123456789 ")
check("empty mapname", h1.wait("SERVERMSG") == "SERVERMSG UPDATEBATTLEINFO failed - invalid mapname send: ")
h1.send("UPDATEBATTLEINFO 0 1 123456789 A\tB")
check("tab mapname", h1.wait("SERVERMSG") == "SERVERMSG UPDATEBATTLEINFO failed - invalid mapname send: A\tB")
o1.drain(); h1.drain(); m1.drain()
h1.send("UPDATEBATTLEINFO 0 1 123456789 NewMap")
check("no change -> no broadcast", m1.waitNo("UPDATEBATTLEINFO") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain()

print("=== 10. STARTRECTS ===")
h1.send("ADDSTARTRECT 0 10 20 30 40")
check("add rect", m1.wait("ADDSTARTRECT") == "ADDSTARTRECT 0 10 20 30 40")
h1.send("ADDSTARTRECT 1 5 6 7 8")
check("add rect 2", m1.wait("ADDSTARTRECT") == "ADDSTARTRECT 1 5 6 7 8")
h1.send("ADDSTARTRECT 0 10 20 30 -5")
check("bad coords", h1.wait("SERVERMSG") == "SERVERMSG invalid ADDSTARTRECT received")
o1.drain(); h1.drain(); m1.drain()
h1.send("REMOVESTARTRECT 0")
check("remove rect", m1.wait("REMOVESTARTRECT") == "REMOVESTARTRECT 0")
h1.send("REMOVESTARTRECT 5")
check("remove missing rect", h1.wait("SERVERMSG") == "SERVERMSG invalid rect removed: 5")
m1.send("ADDSTARTRECT 0 1 2 3 4")
check("non-host rect ignored", m1.waitNo("ADDSTARTRECT") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain()

print("=== 11. UNITS ===")
h1.send("DISABLEUNITS tank goliath")
check("disable units", m1.wait("DISABLEUNITS") == "DISABLEUNITS tank goliath")
h1.send("DISABLEUNITS goliath scv")
check("disable dedup", m1.wait("DISABLEUNITS") == "DISABLEUNITS scv")
h1.send("ENABLEUNITS scv")
check("enable units", m1.wait("ENABLEUNITS") == "ENABLEUNITS scv")
h1.send("ENABLEUNITS tank nope")
check("enable partial", m1.wait("ENABLEUNITS") == "ENABLEUNITS tank")
h1.send("ENABLEUNITS nope")
check("enable nothing -> silent", m1.waitNo("ENABLEUNITS") is None, "unexpected")
h1.send("ENABLEALLUNITS")
check("enable all", m1.wait("ENABLEALLUNITS") == "ENABLEALLUNITS")
m1.send("DISABLEUNITS x")
check("non-host units ignored", m1.waitNo("DISABLEUNITS") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain()

print("=== 12. BOTS ===")
m1.send("ADDBOT bot1 0 3 AIDLL1")
check("add bot", h1.wait("ADDBOT") == "ADDBOT 1 bot1 mmb 0 3 AIDLL1")
m1.send("ADDBOT bot1 0 3 AIDLL1")
check("duplicate bot", m1.wait("FAILED") == "FAILED msg=Bot already exists!\tcmd=ADDBOT")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
o1.send("ADDBOT x 0 0 0")
check("add bot outside battle", o1.wait("FAILED") == "FAILED msg=Couldn't find battle\tcmd=ADDBOT")
o1.drain()
m1.send("UPDATEBOT bot1 1 4")
check("update bot (owner)", h1.wait("UPDATEBOT") == "UPDATEBOT 1 bot1 1 4")
h1.drain(); m1.drain()
h1.send("UPDATEBOT bot1 5 6")
check("update bot (host)", m1.wait("UPDATEBOT") == "UPDATEBOT 1 bot1 5 6")
h1.drain(); m1.drain()
m2.send("UPDATEBOT bot1 1 5")
check("update bot (stranger) ignored", m1.waitNo("UPDATEBOT") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
m1.send("REMOVEBOT bot1")
check("remove bot", h1.wait("REMOVEBOT") == "REMOVEBOT 1 bot1")
m2.send("REMOVEBOT bot1")
check("remove missing bot ignored", h1.waitNo("REMOVEBOT") is None, "unexpected")
o1.drain(); h1.drain(); m1.drain(); m2.drain()
o1.send("UPDATEBOT x 0 0")
check("update bot outside battle", o1.wait("FAILED") == "FAILED msg=Couldn't find battle\tcmd=UPDATEBOT")
o1.send("REMOVEBOT x")
check("remove bot outside battle", o1.wait("FAILED") == "FAILED msg=Couldn't find battle\tcmd=REMOVEBOT")
o1.drain(); h1.drain(); m1.drain()

print("=== 13. MYBATTLESTATUS errors ===")
m1.send("MYBATTLESTATUS abc 12")
check("invalid status", m1.wait("FAILED") == "FAILED msg=invalid status: abc.\tcmd=MYBATTLESTATUS")
m1.send("MYBATTLESTATUS 0 abc")
check("invalid teamcolor", m1.wait("FAILED") == "FAILED msg=invalid teamcolor: abc.\tcmd=MYBATTLESTATUS")
o1.drain(); h1.drain(); m1.drain()

NEG = 2147483647
NEG_CALC = (15 << 24) | (3 << 22) | (25 << 11) | (1 << 10) | (15 << 6) | (15 << 2) | (1 << 1)
m1.send("MYBATTLESTATUS -1 12")
check("negative status FAILED", m1.wait("FAILED") == "FAILED msg=invalid status is below 0: -1. Please update your lobby!\tcmd=MYBATTLESTATUS")
check("negative status still applied", h1.wait("CLIENTBATTLESTATUS") == "CLIENTBATTLESTATUS mmb %d 12" % NEG_CALC)
check("negative status specs 2->1", m1.wait("UPDATEBATTLEINFO") == "UPDATEBATTLEINFO 1 1 1 123456789 NewMap")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

m1.send("LEAVEBATTLE")
h1.wait("LEFTBATTLE 1 mmb")
m1.send("MYBATTLESTATUS 0 0")
check("status outside battle", m1.wait("FAILED") == "FAILED msg=not inside a battle\tcmd=MYBATTLESTATUS")
o1.drain(); h1.drain(); m1.drain(); m2.drain()

print()
if failures:
    print("FAILURES (%d): %s" % (len(failures), failures))
    sys.exit(1)
print("ALL BATTLEMOD TESTS PASSED")
