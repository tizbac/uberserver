package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// FloodLimits mirrors the flood_limits entries in DataHandler.
type FloodLimits struct {
	bytesPerSecond int
	seconds        int
	msgLength      int
}

// Client mirrors Client.py: one server-side connected client.
type Client struct {
	ipAddress string
	localIP   string
	port      int

	// fields also in user db
	userID       int
	username     string
	password     string
	registerDate time.Time
	lastLogin    time.Time
	lastIP       string
	lastAgent    string
	lastID       int
	lastSysID    string
	lastMacID    string
	ingameTime   int
	access       string
	email        string
	bot          bool

	// session
	sessionID    int
	debug        bool
	static       bool
	sendError    bool
	removing     bool
	tls          bool
	compat       map[string]bool // holds compatibility flags
	countryCode  string
	agent        string
	status       int
	accessLevels map[string]bool
	loggedIn     bool

	// server<->client comms
	writeMu          sync.Mutex
	bufferSend       bool // if true, write all sends to a buffer (must not be used when a client is logging in but didn't yet receive full server state!)
	buffer           string
	msgID            string
	msgSendBuffer    []string
	sendingMessage   string
	msgLengthHistory map[int]int

	// channels
	channels map[string]bool
	ignored  map[int]bool
	lastSaid map[string]map[string][]string

	// for if we are a bridge bot
	bridge map[string]map[string]int // location -> external_id -> bridged_id

	// perhaps these are unused?
	cpu      float64
	data     string
	lastData int64

	// time-stamps for encrypted data
	incomingMsgCtr int
	outgoingMsgCtr int

	// battle stuff
	isInGame       bool
	scriptPassword *string
	battleBots     map[string]*Bot
	currentBattle  *int // battle_id
	pendingBattle  *int // battle_id
	wentIngame     int
	spectator      bool
	battleStatus   map[string]string
	teamColor      any // string initially, int after MYBATTLESTATUS (mirrors Python's str/int mix)
	hostPort       *int
	udpPort        int

	// connection
	conn         net.Conn
	connectTime  time.Time
	removeReason string
}

// newClient mirrors Client.__init__ (initial setup for the connected client).
func newClient(address net.Addr, sessionID int) *Client {
	host, portStr, _ := net.SplitHostPort(address.String())
	port, _ := parseInt(portStr)

	// detects if the connection is from this computer
	if strings.HasPrefix(host, "127.") {
		if server.onlineIP != "" {
			host = server.onlineIP
		} else if server.localIP != "" {
			host = server.localIP
		}
	}

	now := time.Now()
	c := &Client{
		ipAddress: host,
		localIP:   host,
		port:      port,

		userID:       -1,
		username:     "",
		password:     "",
		registerDate: now,
		lastLogin:    now,
		lastIP:       host,
		lastID:       0,
		ingameTime:   0,
		access:       "fresh",
		email:        "",
		bot:          false,

		sessionID:    sessionID,
		compat:       map[string]bool{},
		countryCode:  "??",
		agent:        "",
		status:       12,
		accessLevels: map[string]bool{"fresh": true, "everyone": true},
		loggedIn:     false,

		msgLengthHistory: map[int]int{},

		channels: map[string]bool{},
		ignored:  map[int]bool{},
		lastSaid: map[string]map[string][]string{},

		bridge: map[string]map[string]int{},

		cpu:      0,
		lastData: now.Unix(),

		incomingMsgCtr: 0,
		outgoingMsgCtr: 1,

		isInGame:     false,
		battleBots:   map[string]*Bot{},
		wentIngame:   0,
		spectator:    false,
		battleStatus: map[string]string{"ready": "0", "id": "0000", "ally": "0000", "mode": "0", "sync": "00", "side": "00", "handicap": "0000000"},
		teamColor:    "0",

		udpPort:     0,
		connectTime: now,
	}
	c.setFlagByIP(c.ipAddress, true)
	return c
}

func parseInt(s string) (int, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid int: %s", s)
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (c *Client) setMsgID(msg string) string {
	c.msgID = ""

	if !strings.HasPrefix(msg, "#") {
		return msg
	}

	parts := strings.Split(msg, " ")
	test := parts[0][1:]

	if !isDigits(test) {
		return msg
	}

	c.msgID = "#" + test + " "
	return strings.Join(parts[1:], " ")
}

func (c *Client) setFlagByIP(ip string, force bool) {
	cc := lookupCountry(ip)
	if force || cc != "??" {
		c.countryCode = cc
	}
}

// handle mirrors Client.Handle (data received from the client). The whole
// run is a state section: python processes a client's data on the reactor
// thread, so command handlers run atomically with respect to other
// clients' commands here as well.
func (c *Client) handle(data string) {
	server.stateLock()
	defer server.stateUnlock()

	var limits FloodLimits
	if c.bot {
		limits = server.floodLimits["bot"]
	} else if l, ok := server.floodLimits[c.access]; ok {
		limits = l
	} else {
		limits = server.floodLimits["fresh"]
	}

	now := int(time.Now().Unix())
	c.lastData = int64(now) // data received, store time to detect disconnects

	c.msgLengthHistory[now] += len(data)

	total := 0
	for sec, n := range c.msgLengthHistory {
		if sec < now-(limits.seconds-1) {
			delete(c.msgLengthHistory, sec)
		} else {
			total += n
		}
	}

	if total > limits.bytesPerSecond*limits.seconds {
		c.Send(fmt.Sprintf("SERVERMSG No flooding (over %d per second for %d seconds)", limits.bytesPerSecond, limits.seconds))
		c.reportFloodBreach("flood limit", total)
		c.remove("Kicked for flooding (" + c.access + ")")
		return
	}

	// keep appending until we see at least one newline
	c.data += data

	if !strings.Contains(c.data, "\n") {
		// if far too much data has accumulated without hitting flood limits and without a newline, just clear it
		if len(c.data) > limits.msgLength*16 {
			c.data = ""
			c.Send("SERVERMSG Max client data cache was exceeded, some of your data was dropped by the server")
			c.reportFloodBreach("max client data cache ", 0)
		}
		return
	}

	c.handleProtocolCommands(strings.Split(c.data, "\n"), limits)
}

func (c *Client) handleProtocolCommand(cmd string) {
	// probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
	if len(cmd) < 1 {
		return
	}
	server.protocol.handle(c, cmd)
}

func (c *Client) handleProtocolCommands(splitData []string, limits FloodLimits) {
	// either a list of commands, or a list of encrypted data blobs which may
	// contain embedded (post-decryption) NLs
	rawBlobs := splitData[:len(splitData)-1]

	// will be a single newline in most cases, or an incomplete command which
	// should be saved for a later time when more data is in buffer
	c.data = splitData[len(splitData)-1]

	commandsBuffer := []string{}
	for _, blob := range rawBlobs {
		if len(blob) == 0 {
			continue
		}
		commandsBuffer = append(commandsBuffer, strings.TrimLeft(strings.TrimRight(blob, "\r"), " "))
	}

	for _, command := range commandsBuffer {
		if len(command) > limits.msgLength {
			c.Send(fmt.Sprintf("SERVERMSG message length limit of %d chars was exceeded: command \"%s...\" dropped.", limits.msgLength, command[:16]))
			c.reportFloodBreach(fmt.Sprintf("max message length (cmd=\\%s...)\\)", command[:16]), len(command))
			continue
		}
		c.handleProtocolCommand(command)
	}
}

func (c *Client) reportFloodBreach(typ string, byteCount int) {
	userDetails := fmt.Sprintf("<%s>, session_id: %d", c.username, c.sessionID)
	errMsg := fmt.Sprintf("%s for '%s' breached by %s, had %d bytes", typ, c.access, userDetails, byteCount)
	server.protocol.broadcastModerator(errMsg)
	log.Printf("%s", errMsg)
}

// realSend mirrors Client.RealSend.
func (c *Client) realSend(data string) {
	if data == "" {
		return
	}

	rawMsg := data
	if strings.HasPrefix(data, "#") {
		if i := strings.Index(data, " "); i >= 0 {
			rawMsg = data[i+1:]
		}
	}
	command := rawMsg
	if i := strings.Index(rawMsg, " "); i >= 0 {
		command = rawMsg[:i]
	}
	server.mu.Lock()
	server.outboundCommandStats[command]++
	server.mu.Unlock()

	c.writeMu.Lock()
	_, err := c.conn.Write(append([]byte(data), '\n'))
	c.writeMu.Unlock()
	if err != nil {
		log.Printf("Error writing to client %s: %s", c.username, err)
		c.conn.Close()
	}
}

// Send mirrors Client.Send. Callers must run inside a state section (see
// Server.stateLock): the message is queued into server.pendingSends and
// written to the connection by the section's stateUnlock, so no
// connection I/O ever happens while the state lock is held.
func (c *Client) Send(data string) {
	if c.msgID != "" {
		data = c.msgID + data
	}
	if c.bufferSend {
		c.buffer += data + "\n"
		return
	}
	c.sendQueued(data)
}

// sendQueued appends a raw message (no msgID prefix) to the client's
// outgoing queue. Callers must run inside a state section.
func (c *Client) sendQueued(data string) {
	server.pendingSends[c] = append(server.pendingSends[c], data)
}

// flushBuffer mirrors Client.flushBuffer.
func (c *Client) flushBuffer() {
	if c.buffer == "" {
		return
	}
	buf := c.buffer
	c.buffer = ""
	c.bufferSend = false
	c.sendQueued(buf)
}

// remove mirrors Client.Remove (abort the connection; the read loop then
// calls protocol._remove with the reason). The actual conn close is deferred
// to the end of the enclosing state section (see Server.stateUnlock) so
// messages queued via Send during the section reach the connection first,
// like twisted's loseConnection. Callers must run inside a state section.
func (c *Client) remove(reason string) {
	c.removeReason = reason
	server.pendingCloses = append(server.pendingCloses, c)
}

// closeConn performs the deferred connection close. Must run outside any
// state section.
func (c *Client) closeConn() {
	c.writeMu.Lock()
	c.conn.Close()
	c.writeMu.Unlock()
}

// startTLS mirrors the Chat.StartTLS transport upgrade. Holds writeMu for
// the duration of the handshake so concurrent realSend writes are blocked
// (and then go over the new TLS conn) instead of corrupting the stream.
func (c *Client) startTLS() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	tlsConn := tls.Server(c.conn, server.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Error in handling data from client: %s", err)
		c.conn.Close()
		return
	}
	c.conn = tlsConn
	c.tls = true
}

// channelUser interface.
func (c *Client) UserID() int      { return c.userID }
func (c *Client) Username() string { return c.username }
func (c *Client) LastIP() string   { return c.lastIP }

func (c *Client) isAdmin() bool {
	return c.accessLevels["admin"]
}

func (c *Client) isMod() bool {
	return c.isAdmin() || c.accessLevels["mod"]
}

// calcAccessMap mirrors Protocol._calc_access.
func calcAccessMap(access string) map[string]bool {
	inherit := map[string][]string{
		"mod":   {"user"},
		"admin": {"mod", "user"},
	}
	var inherited []string
	if levels, ok := inherit[access]; ok {
		inherited = append([]string{}, levels...)
	} else {
		inherited = []string{access}
	}
	has := false
	for _, l := range inherited {
		if l == access {
			has = true
			break
		}
	}
	if !has {
		inherited = append(inherited, access)
	}
	m := map[string]bool{"everyone": true}
	for _, l := range inherited {
		m[l] = true
	}
	return m
}

// calcAccess mirrors Protocol._calc_access.
func (c *Client) calcAccess() {
	c.accessLevels = calcAccessMap(c.access)
}

// userRef interface.
func (c *Client) Access() string              { return c.access }
func (c *Client) HasAccess(level string) bool { return c.accessLevels[level] }
func (c *Client) Bot() bool                   { return c.bot }

func (c *Client) isHosting() bool {
	return c.currentBattle != nil && server.battles[*c.currentBattle].host == c.sessionID
}

// readLoop is the Go equivalent of Chat.dataReceived: reads chunks from the
// connection and feeds them to handle(). Reads from c.conn directly so that
// it transparently follows the conn swap performed by startTLS.
func (c *Client) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, err := c.conn.Read(buf)
		if n > 0 {
			data := string(buf[:n])
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Error in handling data from client: %s %s:%d\ncommand: %s", c.username, c.ipAddress, c.port, c.removePWs(data))
					}
				}()
				c.handle(data)
			}()
		}
		if err != nil {
			return
		}
	}
}

// timeoutLoop mirrors Twisted's TimeoutMixin (60s; reset only for
// authenticated users when data is received).
func (c *Client) timeoutLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		server.stateLock()
		var expired bool
		if c.username != "" {
			expired = time.Now().Unix()-c.lastData > 60
		} else {
			expired = time.Since(c.connectTime) > 60*time.Second
		}
		server.stateUnlock()
		if expired {
			c.conn.Close()
			return
		}
	}
}

// removePWs removes the password from a LOGIN message, to avoid it
// appearing in the logfile.
func (c *Client) removePWs(data string) string {
	if !strings.Contains(data, "LOGIN") {
		return data
	}
	words := strings.Split(data, " ")
	if strings.HasPrefix(data, "#") && len(words) >= 4 {
		words[3] = "*"
	} else if strings.HasPrefix(data, "LOGIN") && len(words) >= 3 {
		words[2] = "*"
	}
	return strings.Join(words, " ")
}
