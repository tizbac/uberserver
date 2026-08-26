import socket, time, threading, sys, ssl, queue, re

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
                    print("[%s] <- CLOSED" % self.name)
                    return
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
        # returns the first line starting with prefix, consuming it
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

    def waitNo(self, prefix, timeout=1.5):
        # None if no line with prefix arrives within timeout
        time.sleep(timeout)
        with self.lock:
            for i, l in enumerate(self.lines):
                if l.startswith(prefix):
                    del self.lines[i]
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

def relogin(name, sentence=""):
    # user already exists; just log in again
    c = C(name)
    if sentence:
        c.send("LOGIN %s 5S2YxFmBmhF3WTbY37t5KQ== 0 192.168.1.10 %s" % (name, sentence))
    else:
        c.send("LOGIN %s 5S2YxFmBmhF3WTbY37t5KQ==" % name)
    c.wait("ACCEPTED")
    c.drain()
    return c

print("=== setup: admin + 3 users ===")
# admin was created at server startup with plaintext password 'topsecret'
admin = C("admin")
admin.send("LOGIN admin 6oR5iLpZcn2/TjTudXJtww==")
admin.wait("ACCEPTED")
admin.drain()

u01 = login("u01", "TestAgent\t12345678 9abcdef\tb u")
u02 = login("u02")
u03 = login("u03", "TestAgent\t0\tu")

print("=== 1. access check: plain user denied mod command ===")
u01.send("BAN u03 1 testban")
check("insufficient rights", u01.wait("SERVERMSG") == "SERVERMSG BAN failed. Insufficient rights.")
u01.drain()

print("=== 2. GETUSERID ===")
admin.send("GETUSERID u01")
check("getuserid online", admin.wait("SERVERMSG") == "SERVERMSG The ID for <u01> is 12345678 9abcdef")
admin.send("GETUSERID ghost")
check("getuserid unknown", admin.wait("SERVERMSG") == "SERVERMSG User not found.")
admin.drain()

print("=== 3. FINDIP / GETIP ===")
admin.send("FINDIP 193.31.249.233")
for n in ("admin", "u01", "u02", "u03"):
    check("findip %s" % n, admin.wait("SERVERMSG <%s> is currently bound to 193.31.249.233." % n) == "SERVERMSG <%s> is currently bound to 193.31.249.233." % n)
admin.send("FINDIP 10.9.8.7")
check("findip nobody", admin.waitNo("SERVERMSG") is None, "unexpected message")
admin.send("GETIP u01")
check("getip online", admin.wait("SERVERMSG") == "SERVERMSG <u01> is currently bound to 193.31.249.233")
admin.drain()

print("=== 4. SETBOTMODE ===")
admin.send("SETBOTMODE u02 true")
check("botmode msg", admin.wait("SERVERMSG") == "SERVERMSG Botmode for <u02> successfully changed to True")
check("botmode clientstatus u02", u02.wait("CLIENTSTATUS") == "CLIENTSTATUS u02 64")
check("botmode clientstatus u03", u03.wait("CLIENTSTATUS") == "CLIENTSTATUS u02 64")
u01.drain() # u01 also received the 64 broadcast; drop it so the 0 check below is clean
admin.send("SETBOTMODE u02 false")
check("botmode off msg", admin.wait("SERVERMSG") == "SERVERMSG Botmode for <u02> successfully changed to False")
check("botmode off clientstatus", u01.wait("CLIENTSTATUS") == "CLIENTSTATUS u02 0")
admin.drain(); u01.drain()

print("=== 5. BROADCAST / BROADCASTEX / ADMINBROADCAST ===")
admin.send("BROADCAST hello everyone")
for c in (u01, u02, u03):
    check("broadcast %s" % c.name, c.wait("BROADCAST") == "BROADCAST hello everyone")
admin.wait("BROADCAST hello everyone")
admin.send("BROADCASTEX boxed msg")
check("broadcastex u01", u01.wait("SERVERMSGBOX") == "SERVERMSGBOX boxed msg")
# admin also got the BROADCASTEX SERVERMSGBOX; drop it so the ADMINBROADCAST
# wait below isn't shadowed by the stale line (SERVERMSGBOX starts with SERVERMSG)
u02.drain(); u03.drain(); admin.drain()
admin.send("ADMINBROADCAST hi admins")
check("adminbroadcast admin", admin.wait("SERVERMSG") == "SERVERMSG Admin broadcast: hi admins")
check("adminbroadcast not to user", u01.waitNo("Admin broadcast") is None, "user got admin broadcast")
admin.drain(); u01.drain()

print("=== 6. BAN (online target) ===")
admin.send("BAN u02 7 testban")
check("banned target msg", u02.wait("SERVERMSG You were kicked from the server (banned)") == "SERVERMSG You were kicked from the server (banned)")
check("banned target box", u02.wait("SERVERMSGBOX You were kicked from the server (banned)") == "SERVERMSGBOX You were kicked from the server (banned)")
check("ban kicked msg", admin.wait("SERVERMSG Kicked") == "SERVERMSG Kicked <u02> from the server")
# email is None: verification is disabled, so REGISTER drops the email (mirrors python)
check("ban success msg", admin.wait("SERVERMSG Successfully banned") == "SERVERMSG Successfully banned u02, 193.31.249.233, None for 7.0 days.")
admin.drain()

print("=== 7. LISTBANS / UNBAN ===")
admin.send("LISTBANS")
check("banlist header", admin.wait("SERVERMSG -- Banlist --") == "SERVERMSG -- Banlist --")
banline = admin.wait("SERVERMSG u02,")
m = re.match(r"^SERVERMSG u02, 193\.31\.249\.233,  :: 'testban' :: ends \d{4}-\d{2}-\d{2} \d{2}:\d{2} \(admin\)$", banline)
check("banlist entry", m is not None, repr(banline))
check("banlist footer", admin.wait("SERVERMSG -- End Banlist --") == "SERVERMSG -- End Banlist --")
admin.drain()
admin.send("UNBAN u02")
check("unban", admin.wait("SERVERMSG") == "SERVERMSG Successfully removed 1 bans relating to u02")
admin.send("UNBAN u02")
check("unban none left", admin.wait("SERVERMSG") == "SERVERMSG No matching bans for u02")
admin.drain()

print("=== 8. BANSPECIFIC / UNBAN ip ===")
admin.send("BANSPECIFIC 192.168.99.99 1 specificban")
check("banspecific ip", admin.wait("SERVERMSG") == "SERVERMSG Successfully banned 192.168.99.99 for 1.0 days")
admin.send("BANSPECIFIC nobodyknows123 1 x")
check("banspecific nomatch", admin.wait("SERVERMSG") == "SERVERMSG Unable to match 'nobodyknows123' to username/ip/email")
admin.send("UNBAN 192.168.99.99")
check("unban ip", admin.wait("SERVERMSG") == "SERVERMSG Successfully removed 1 bans relating to 192.168.99.99")
admin.drain()

print("=== 9. BLACKLIST family ===")
admin.send("BLACKLIST hawtmail.com badprovider")
check("blacklist add", admin.wait("SERVERMSG") == "SERVERMSG Successfully added hawtmail.com to blacklist")
admin.send("BLACKLIST hawtmail.com again")
check("blacklist dup", admin.wait("SERVERMSG") == "SERVERMSG Domain hawtmail.com is already blacklisted")
admin.send("BLACKLIST nodot")
check("blacklist invalid", admin.wait("SERVERMSG") == "SERVERMSG invalid domain 'nodot', contains no '.'")
admin.send("LISTBLACKLIST")
check("blacklist header", admin.wait("SERVERMSG -- Blacklist --") == "SERVERMSG -- Blacklist --")
check("blacklist entry", admin.wait("SERVERMSG hawtmail.com") == "SERVERMSG hawtmail.com :: 'badprovider' (admin)")
check("blacklist footer", admin.wait("SERVERMSG -- End Blacklist--") == "SERVERMSG -- End Blacklist--")
admin.send("UNBLACKLIST hawtmail.com")
check("unblacklist", admin.wait("SERVERMSG") == "SERVERMSG Sucessfully removed hawtmail.com from blacklist")
admin.send("UNBLACKLIST hawtmail.com")
check("unblacklist missing", admin.wait("SERVERMSG") == "SERVERMSG Unable to remove hawtmail.com, entry doesn't exist")
admin.drain()

print("=== 10. KICK (u02 re-login then kick) ===")
u02 = relogin("u02")
admin.send("KICK u02 byebye")
check("kick target msg", u02.wait("SERVERMSG You were kicked from the server (byebye)") == "SERVERMSG You were kicked from the server (byebye)")
check("kick target box", u02.wait("SERVERMSGBOX You were kicked from the server (byebye)") == "SERVERMSGBOX You were kicked from the server (byebye)")
check("kick kicker msg", admin.wait("SERVERMSG") == "SERVERMSG Kicked <u02> from the server")
admin.send("KICK ghost")
check("kick offline", admin.wait("SERVERMSG") == "SERVERMSG User <ghost> was not online")
admin.drain()

print("=== 11. SETACCESS / LISTMODS ===")
admin.send("SETACCESS u01 mod")
check("setaccess ok", admin.wait("OK") == "OK cmd=SETACCESS") # OK goes to the requester
# status is the 7-bit string bot|access|rank3|away|ingame parsed as BINARY:
# mod => 0100000b = 32
check("setaccess clientstatus", u03.wait("CLIENTSTATUS") == "CLIENTSTATUS u01 32")
u01.send("LISTMODS")
# LISTMODS is in the admin level of the restricted table, so a mod is rejected
# by the dispatcher before in_LISTMODS's (dead in python) 'mod' check runs
check("listmods mod denied", u01.wait("SERVERMSG") == "SERVERMSG LISTMODS failed. Insufficient rights.")
admin.send("LISTMODS")
check("listmods admins", admin.wait("SERVERMSG Admins:") == "SERVERMSG Admins: admin ")
check("listmods mods", admin.wait("SERVERMSG Mods:") == "SERVERMSG Mods: u01 ")
u01.drain(); admin.drain()
admin.send("SETACCESS u01 super")
check("setaccess invalid", admin.wait("SERVERMSG") == "SERVERMSG Invalid access mode, only user, mod, admin is valid.")
admin.send("SETACCESS ghost mod")
check("setaccess unknown", admin.wait("SERVERMSG") == "SERVERMSG User not found.")
admin.send("SETACCESS u01 user")
check("setaccess back", admin.wait("OK") == "OK cmd=SETACCESS")
admin.drain(); u03.drain()

print("=== 12. SETMINSPRINGVERSION closes botflag battle ===")
u03.send("OPENBATTLE 0 0 * 12345 8 123456789 0 -123456789 spring\t105.0.1\tTestMap\tTest Title\tTestMod")
opened = u03.wait("BATTLEOPENED")
bid = opened.split()[1]
# battle.name is the battle channel name, the last tab-separated field
bname = opened.split('\t')[-1]
u03.wait("OPENBATTLE %s" % bid)
u03.drain()
admin.send("SETBOTMODE u03 true")
admin.wait("SERVERMSG")
admin.drain()
admin.send("SETMINSPRINGVERSION 106.0")
check("minver saidex (u compat)", u03.wait("SAIDEX") == "SAIDEX %s u03 -- This battle will close -- Spring 106.0 or later is now required by the server. Please join a battle with the new Spring version!" % bname)
check("minver closed", u03.wait("BATTLECLOSED") == "BATTLECLOSED " + bid)
check("minver msg", admin.wait("SERVERMSG") == "SERVERMSG Set Spring engine version to 106.0")
admin.drain(); u03.drain()

print("=== 13. DELETEACCOUNT (offline u02) ===")
# u02 has no email (verification disabled), so no 28-day email ban is issued
admin.send("DELETEACCOUNT u02")
check("delete kick offline", admin.wait("SERVERMSG User") == "SERVERMSG User <u02> was not online")
check("delete scheduled", admin.wait("SERVERMSG Account deletion") == "SERVERMSG Account deletion of <u02> scheduled by <admin>")
admin.send("GETUSERID u02")
check("deleted account still queryable", admin.wait("SERVERMSG") == "SERVERMSG The ID for <u02> is 0 0")
admin.drain()

print("=== 14. RESETUSERPASSWORD (verification off) ===")
admin.send("RESETUSERPASSWORD u01")
check("reset pw inactive", admin.wait("SERVERMSG") == "SERVERMSG Email verification is currently turned off, account recovery is disabled")
admin.drain()

print("=== 15. CREATEBOTACCOUNT ===")
admin.send("CREATEBOTACCOUNT x")
check("botaccount badname", admin.wait("FAILED") == "FAILED msg=Invalid username 'x'\tcmd=CREATEBOTACCOUNT")
admin.send("CREATEBOTACCOUNT newbot")
line = admin.wait("SERVERMSG")
m = re.match(r"^SERVERMSG A new bot account <newbot> has been created, Bot auto-generated password is [A-Za-z0-9]{16}$", line)
check("botaccount created", m is not None, repr(line))
admin.send("CREATEBOTACCOUNT newbot")
check("botaccount dup", admin.wait("FAILED") == "FAILED msg=Username is already in use.\tcmd=CREATEBOTACCOUNT")
admin.send("GETUSERID newbot")
# fresh accounts store last_mac_id/last_sys_id as empty strings (python User model)
check("botaccount exists", admin.wait("SERVERMSG") == "SERVERMSG The ID for <newbot> is  ")
admin.send("CREATEBOTACCOUNT newbot2 pass123 u01")
check("botaccount founder", admin.wait("SERVERMSG") == "SERVERMSG A new bot account <newbot2> has been created, and battle founder <u01>")
admin.send("CREATEBOTACCOUNT newbot3 pass123 ghost")
check("botaccount badfounder", admin.wait("FAILED") == "FAILED msg=User does not exist 'ghost'\tcmd=CREATEBOTACCOUNT")
admin.drain()

print("=== 16. CLEANUP / STATS ===")
admin.send("CLEANUP")
line = admin.wait("SERVERMSG")
m = re.match(r"^SERVERMSG Cleanup complete: \d+ deletions, \d+ mismatches$", line)
check("cleanup report", m is not None, repr(line))
admin.drain()
admin.send("STATS")
check("stats msg", admin.wait("SERVERMSG") == "SERVERMSG Stats were printed in the server logfile")
admin.drain()

print()
if failures:
    print("FAILURES (%d): %s" % (len(failures), failures))
    sys.exit(1)
print("ALL MODADMIN TESTS PASSED")
