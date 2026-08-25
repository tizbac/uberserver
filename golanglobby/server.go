package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// userRef is a reference to a user that is either online (*Client) or was
// read from the db (*OfflineUser). It mirrors the duck-typed results of
// Python's DataHandler.clientFromID/clientFromUsername (fromdb=True).
type userRef interface {
	channelUser
	Access() string
	HasAccess(level string) bool
	Bot() bool
}

// Server mirrors DataHandler.py: the root object holding the db handlers,
// online state and channel state.
type Server struct {
	logFilename string

	localIP  string
	onlineIP string

	sessionID  int // next session id to hand out
	nextBattle int // python: nextbattle = 0; first battle id is 1

	port    int
	natPort int

	minSpringVersion string
	redirect         string
	disableSignupURL string

	agreement []string
	motd      []string
	iphubXkey string
	mailUser  string

	trustedProxies   map[string]bool
	trustedProxyFile *string

	serverName    string
	serverVersion string

	sighup  bool
	running bool

	userDB         *UserDB
	banDB          *BanDB
	verificationDB *VerificationDB
	channelDB      *ChannelDB
	bridgedUserDB  *BridgedUserDB
	contentDB      *ContentDB

	ChanServ  *ChanServ
	protocol  *Protocol
	tlsConfig *tls.Config

	sqlURL string
	censor bool

	certFile string
	keyFile  string

	startTime time.Time

	// stats
	inboundCommandStats  map[string]int
	outboundCommandStats map[string]int
	flagStats            map[string]int
	agentStats           map[string]int
	tlsStats             int
	nLoginStats          int

	// lists of online stuff
	channels  map[string]*Channel // channame->channel/battle
	battles   map[int]*Battle     // battle_id->battle
	usernames map[string]*Client  // username->client
	userIDs   map[int]*Client     // user_id->client
	clients   map[int]*Client     // session_id->client

	bridgedLocations map[string]int            // location->bridge_user_id
	bridgedIDs       map[int]*BridgedClient    // bridged_id->bridgedClient
	bridgedUsernames map[string]*BridgedClient // bridgeUsername->bridgedClient

	// rate limits
	nonResRegistrations map[int]bool   // user_id
	ipTypeCache         map[string]int // ip->state (iphub: 0=non-residential, 1=residential, 2=both)
	recentRegistrations map[string]int // ip_address->count
	recentRenames       map[int]int    // user_id->count
	floodLimits         map[string]FloodLimits

	// mu guards all shared state (the maps above, channel/battle state,
	// per-client fields that other clients' commands can mutate). Python runs
	// everything on one reactor thread; here every unit of processing (one
	// client command, one timer tick, the connection lifecycle) runs as a
	// "state section" under mu, so state changes are atomic the same way.
	// Connection writes never happen while mu is held: Client.Send queues
	// into pendingSends during a section and the messages are written after
	// the section ends. Connections marked for removal (Client.remove) are
	// closed in the same post-section flush, after their queued messages,
	// mirroring twisted's loseConnection draining the write buffer.
	mu            sync.Mutex
	muDepth       int // >0 while a state section is active (guarded by mu)
	pendingSends  map[*Client][]string
	pendingCloses []*Client
}

var server *Server

// newServer mirrors DataHandler.__init__ (defaults come from Config).
func newServer(cfg *Config) *Server {
	var trustedProxyFile *string
	if cfg.TrustedProxyFile != "" {
		v := cfg.TrustedProxyFile
		trustedProxyFile = &v
	}
	s := &Server{
		logFilename:          cfg.LogFileName,
		port:                 cfg.Port,
		natPort:              cfg.EffectiveNATPort(),
		minSpringVersion:     cfg.MinSpringVersion,
		redirect:             cfg.Redirect,
		disableSignupURL:     cfg.DisableSignupURL,
		trustedProxyFile:     trustedProxyFile,
		serverName:           "TASSERVER",
		serverVersion:        "unknown",
		sighup:               cfg.Sighup,
		running:              true,
		sqlURL:               cfg.SQLURL,
		censor:               cfg.Censor,
		certFile:             cfg.CertFile,
		keyFile:              cfg.KeyFile,
		startTime:            time.Now(),
		trustedProxies:       map[string]bool{},
		inboundCommandStats:  map[string]int{},
		outboundCommandStats: map[string]int{},
		flagStats:            map[string]int{},
		agentStats:           map[string]int{},
		channels:             map[string]*Channel{},
		battles:              map[int]*Battle{},
		usernames:            map[string]*Client{},
		userIDs:              map[int]*Client{},
		clients:              map[int]*Client{},
		bridgedLocations:     map[string]int{},
		bridgedIDs:           map[int]*BridgedClient{},
		bridgedUsernames:     map[string]*BridgedClient{},
		pendingSends:         map[*Client][]string{},
		nonResRegistrations:  map[int]bool{},
		ipTypeCache:          map[string]int{},
		recentRegistrations:  map[string]int{},
		recentRenames:        map[int]int{},
		floodLimits: map[string]FloodLimits{
			"fresh": {msgLength: 1000, bytesPerSecond: 1000, seconds: 2}, // also the default
			"user":  {msgLength: 10000, bytesPerSecond: 2000, seconds: 10},
			"bot":   {msgLength: 10000, bytesPerSecond: 50000, seconds: 10},
			"mod":   {msgLength: 10000, bytesPerSecond: 2000, seconds: 10},
			"admin": {msgLength: 10000, bytesPerSecond: 2000, seconds: 10},
		},
	}
	s.detectIP()
	return s
}

// stateLock begins a state section: mu is held until the matching
// stateUnlock. Sends made inside the section are queued (see Client.Send)
// and written to the connections by stateUnlock, so no connection I/O
// happens while mu is held. Sections may nest; only the outermost unlock
// flushes the queued sends.
func (s *Server) stateLock() {
	s.mu.Lock()
	s.muDepth++
}

func (s *Server) stateUnlock() {
	s.muDepth--
	if s.muDepth > 0 {
		s.mu.Unlock()
		return
	}
	queued := s.pendingSends
	s.pendingSends = map[*Client][]string{}
	closed := s.pendingCloses
	s.pendingCloses = nil
	s.mu.Unlock()
	flushPendingSends(queued)
	for _, c := range closed {
		c.closeConn()
	}
}

// flushPendingSends writes queued messages to the connections. Must be
// called without holding mu.
func flushPendingSends(queued map[*Client][]string) {
	for client, msgs := range queued {
		for _, msg := range msgs {
			client.realSend(msg)
		}
	}
}

// init mirrors DataHandler.init.
func (s *Server) init() error {
	s.parseFiles()
	s.getServerVersion()

	var err error
	s.userDB, s.banDB, s.verificationDB, s.channelDB, s.bridgedUserDB, s.contentDB, err =
		newDB(s.sqlURL, s.mailUser != "")
	if err != nil {
		return err
	}
	s.minSpringVersion = s.contentDB.getMinSpringVersion()

	s.protocol = newProtocol(s)

	s.setupChannels()

	admins, _ := s.userDB.listMods()
	if admins == "" {
		log.Println("No admin exist, please enter username and password to create new one")
		var username string
		fmt.Print("Username: ")
		fmt.Scanln(&username)
		fmt.Print("Password: ")
		var password string
		fmt.Scanln(&password)
		s.userDB.registerUser(username, md5B64(password), "127.0.0.1", "root@localhost", "admin")
		log.Println("User created, no further action required")
	}
	return nil
}

// setupChannels mirrors the channel/battle setup block of DataHandler.init.
func (s *Server) setupChannels() {
	now := time.Now()
	dbChannels := s.channelDB.allChannels()

	for name, row := range dbChannels {
		var c *Channel
		if strings.HasPrefix(name, "__battle__") {
			c = newBattle(name).Channel
		} else {
			c = newChannel(name)
		}
		c.id = row.ID
		if row.OwnerUserID != nil {
			if owner := s.userDB.getClientFromID(*row.OwnerUserID); owner != nil && owner.UserID() != 0 {
				id := owner.UserID()
				c.ownerUserID = &id
			}
		}
		c.antispam = row.Antispam
		c.storeHistory = row.StoreHistory
		c.key = row.Key
		if c.key != nil && (*c.key == "" || *c.key == "*") {
			c.key = nil
		}
		c.lastUsed = row.LastUsed
		if c.lastUsed.IsZero() { // can remove after first run!
			c.lastUsed = now
			s.channelDB.recordUse(c.name)
		}
		c.topicUserID = row.TopicUserID
		c.topic = row.Topic
		s.channels[name] = c
	}

	// set up chanserv
	s.ChanServ = newChanServ(s, &net.TCPAddr{IP: net.ParseIP(s.onlineIP), Port: 0}, s.sessionID)
	for name := range dbChannels {
		s.ChanServ.handleProtocolCommand("JOIN " + name)
	}
	// Python called chanserv.Handle(":register moderator ChanServ") when the
	// 'moderator' channel was missing, but Handle() only dispatches SAID*
	// messages so that call was a silent no-op (see python bug list).

	// set up channel properties
	for _, forward := range s.channelDB.allForwards() {
		from := s.channelDB.channelFromID(forward.FromID)
		to := s.channelDB.channelFromID(forward.ToID)
		if from != nil && to != nil {
			s.channels[from.Name].forwards[to.Name] = true
		}
	}

	for _, op := range s.channelDB.allOperators() {
		row := s.channelDB.channelFromID(op.ChannelID)
		if row == nil {
			continue
		}
		target := s.clientFromIDDB(op.UserID)
		if target == nil {
			continue
		}
		s.channels[row.Name].opUser(s.ChanServ.Client, target)
	}

	for _, ban := range s.channelDB.allBans() {
		row := s.channelDB.channelFromID(ban.ChannelID)
		if row == nil {
			continue
		}
		target := s.clientFromIDDB(ban.UserID)
		if target == nil {
			continue
		}
		var issuer channelUser = s.ChanServ.Client
		if ban.IssuerUserID != nil {
			if i := s.clientFromIDDB(*ban.IssuerUserID); i != nil {
				issuer = i
			}
		}
		duration := ban.Expires.Sub(now)
		s.channels[row.Name].banUser(issuer, target, ban.Expires, ban.Reason, duration)
	}

	for _, ban := range s.channelDB.allBridgedBans() {
		row := s.channelDB.channelFromID(ban.ChannelID)
		if row == nil {
			continue
		}
		target := s.bridgedClientFromID(ban.BridgedID, true)
		if target == nil {
			continue
		}
		var issuer channelUser = s.ChanServ.Client
		if ban.IssuerUserID != nil {
			if i := s.clientFromIDDB(*ban.IssuerUserID); i != nil {
				issuer = i
			}
		}
		duration := ban.Expires.Sub(now)
		s.channels[row.Name].banBridgedUser(issuer, target, ban.Expires, ban.Reason, &duration)
	}

	for _, mute := range s.channelDB.allMutes() {
		row := s.channelDB.channelFromID(mute.ChannelID)
		if row == nil {
			continue
		}
		target := s.clientFromIDDB(mute.UserID)
		if target == nil {
			continue
		}
		var issuer channelUser = s.ChanServ.Client
		if mute.IssuerUserID != nil {
			if i := s.clientFromIDDB(*mute.IssuerUserID); i != nil {
				issuer = i
			}
		}
		duration := mute.Expires.Sub(now)
		s.channels[row.Name].muteUser(issuer, target, mute.Expires, mute.Reason, &duration)
	}
}

// logoutStaleSessions mirrors DataHandler.logout_stale_sessions.
func (s *Server) logoutStaleSessions() {
	now := time.Now()
	var toLogout []int
	for sessionID, client := range s.clients {
		if client.static || client.bot {
			continue
		}
		if now.Sub(client.lastLogin) > 14*24*time.Hour {
			toLogout = append(toLogout, sessionID)
		}
	}
	log.Printf("logging out %d stale sessions", len(toLogout))
	for _, sessionID := range toLogout {
		s.clients[sessionID].remove("reached maximum login duration")
	}
}

// scheduledClean mirrors DataHandler.scheduled_clean.
func (s *Server) scheduledClean() {
	log.Println("scheduled clean...")
	s.ipTypeCache = map[string]int{}
	s.logoutStaleSessions()
	s.userDB.auditAccess()
	s.userDB.clean()
	s.bridgedUserDB.clean()
	s.channelDB.clean()
	s.verificationDB.clean()
	s.banDB.clean()
	log.Println("scheduled clean finished")
}

// shutdown mirrors DataHandler.shutdown.
func (s *Server) shutdown() {
	if s.ChanServ != nil && s.protocol != nil {
		s.protocol.inStats(s.ChanServ.Client, nil)
	}
	s.running = false
}

// parseFiles mirrors DataHandler.parseFiles.
func (s *Server) parseFiles() {
	cert, err := loadCertificates(s.certFile, s.keyFile)
	if err != nil {
		log.Printf("Could not load certificates: %s", err)
	} else {
		s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}

	s.motd = []string{}
	if data, err := os.ReadFile("server_motd.txt"); err != nil {
		log.Printf("Could not load motd: %s", err)
		s.motd = append(s.motd, "You have successfully logged into Uberserver!")
	} else {
		s.motd = splitLines(string(data))
	}

	s.agreement = []string{}
	if data, err := os.ReadFile("server_agreement.txt"); err != nil {
		log.Printf("Could not load user agreement %s", err)
		s.agreement = append(s.agreement, "No user agreement detected. If this server is in production, please report this issue immediately!")
	} else {
		s.agreement = splitLines(string(data))
	}

	s.iphubXkey = ""
	if data, err := os.ReadFile("server_iphub_xkey.txt"); err != nil {
		log.Printf("Could not load server_iphub_xkey.txt: %s", err)
	} else {
		lines := splitLinesTrim(string(data))
		if len(lines) > 0 {
			s.iphubXkey = lines[0]
		}
	}

	s.mailUser = ""
	if data, err := os.ReadFile("server_email_account.txt"); err != nil {
		log.Printf("Could not load server_email_account.txt: %s", err)
	} else {
		lines := splitLinesTrim(string(data))
		if len(lines) > 0 {
			s.mailUser = lines[0]
			log.Printf("Server email account is %s", s.mailUser)
		}
	}

	if s.trustedProxyFile != nil {
		data, err := os.ReadFile(*s.trustedProxyFile)
		if err != nil {
			log.Printf("error whilst loading %s: %s", *s.trustedProxyFile, err)
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			proxy := strings.TrimSpace(line)
			if proxy == "" {
				continue
			}
			if !isDottedQuad(proxy) {
				ips, err := net.LookupHost(proxy)
				if err != nil || len(ips) == 0 {
					continue
				}
				proxy = ips[0]
			}
			s.trustedProxies[proxy] = true
		}
	}
}

// getServerVersion mirrors DataHandler.get_server_version.
func (s *Server) getServerVersion() {
	out, err := exec.Command("git", "describe").Output()
	if err != nil {
		s.serverVersion = "unknown"
		log.Println("Failed to get server version")
		return
	}
	s.serverVersion = strings.TrimSpace(string(out))
}

// clientFromID mirrors DataHandler.clientFromID (online only).
func (s *Server) clientFromID(userID int) *Client {
	return s.userIDs[userID]
}

// clientFromIDDB mirrors DataHandler.clientFromID(user_id, fromdb=True).
func (s *Server) clientFromIDDB(userID int) userRef {
	if c, ok := s.userIDs[userID]; ok {
		return c
	}
	client := s.userDB.getClientFromID(userID)
	if client == nil {
		return nil
	}
	return client
}

// clientFromUsername mirrors DataHandler.clientFromUsername (online only).
func (s *Server) clientFromUsername(username string) *Client {
	return s.usernames[username]
}

// clientFromUsernameDB mirrors DataHandler.clientFromUsername(username, fromdb=True).
func (s *Server) clientFromUsernameDB(username string) userRef {
	if c, ok := s.usernames[username]; ok {
		return c
	}
	client := s.userDB.getClientFromUsername(username)
	if client == nil {
		return nil
	}
	if username != client.Username() {
		return nil // db side is case insensitive!
	}
	client.calcAccess()
	return client
}

// clientFromSession mirrors DataHandler.clientFromSession.
func (s *Server) clientFromSession(sessionID int) *Client {
	if c, ok := s.clients[sessionID]; ok {
		return c
	}
	log.Printf("tried to get client from invalid session_id '%d'", sessionID)
	return nil
}

// bridgedClient mirrors DataHandler.bridgedClient.
func (s *Server) bridgedClient(location, externalID string, fromDB bool) *BridgedClient {
	if bridgeUserID, ok := s.bridgedLocations[location]; ok {
		if bridgeUser := s.clientFromID(bridgeUserID); bridgeUser != nil {
			if bridgedID, ok := bridgeUser.bridge[location][externalID]; ok {
				return s.bridgedIDs[bridgedID]
			}
		}
	}
	if !fromDB {
		return nil
	}
	return s.bridgedUserDB.bridgedClient(location, externalID)
}

// bridgedClientFromID mirrors DataHandler.bridgedClientFromID.
func (s *Server) bridgedClientFromID(bridgedID int, fromDB bool) *BridgedClient {
	if bc, ok := s.bridgedIDs[bridgedID]; ok {
		return bc
	}
	if !fromDB {
		return nil
	}
	return s.bridgedUserDB.bridgedClientFromID(bridgedID)
}

// bridgedClientFromUsername mirrors DataHandler.bridgedClientFromUsername.
func (s *Server) bridgedClientFromUsername(username string, fromDB bool) *BridgedClient {
	if bc, ok := s.bridgedUsernames[username]; ok {
		return bc
	}
	if !fromDB {
		return nil
	}
	return s.bridgedUserDB.bridgedClientFromUsername(username)
}

// channelMuteBanTimeout mirrors DataHandler.channel_mute_ban_timeout.
func (s *Server) channelMuteBanTimeout() {
	now := time.Now()
	chanserv := s.ChanServ
	for _, channel := range s.channels {
		toUnmute := []int{}
		for userID, mute := range channel.muteList {
			if mute.expires.Before(now) {
				toUnmute = append(toUnmute, userID)
			}
		}
		for _, userID := range toUnmute {
			target := s.clientFromIDDB(userID)
			if target == nil {
				continue
			}
			channel.unmuteUser(chanserv.Client, target, "mute expired")
		}

		toUnban := []int{}
		for userID, ban := range channel.ban {
			if ban.expires.Before(now) {
				toUnban = append(toUnban, userID)
			}
		}
		for _, userID := range toUnban {
			target := s.clientFromIDDB(userID)
			if target == nil {
				continue
			}
			channel.unbanUser(chanserv.Client, target)
		}

		toUnbanBridged := []int{}
		for bridgedID, ban := range channel.bridgedBan {
			if ban.expires.Before(now) {
				toUnbanBridged = append(toUnbanBridged, bridgedID)
			}
		}
		for _, bridgedID := range toUnbanBridged {
			// python bug: passed the bridged_id int to unbanBridgedUser,
			// which expected an object with .bridged_id; the expired bridged
			// ban was never removed. Go passes the resolved client.
			bc := s.bridgedClientFromID(bridgedID, false)
			if bc == nil {
				continue
			}
			channel.unbanBridgedUser(chanserv.Client, bc)
		}
	}
}

// decrementDict mirrors DataHandler.decrement_dict: decrease all values by 1,
// remove values <= 0.
func decrementDict[K comparable](d map[K]int) {
	for k, v := range d {
		if v <= 1 {
			delete(d, k)
		} else {
			d[k] = v - 1
		}
	}
}

// decrementRecentRegistrations mirrors DataHandler.decrement_recent_registrations.
func (s *Server) decrementRecentRegistrations() {
	decrementDict(s.recentRegistrations)
}

// decrementRecentRenames mirrors DataHandler.decrement_recent_renames.
func (s *Server) decrementRecentRenames() {
	decrementDict(s.recentRenames)
}

// multicast mirrors DataHandler.multicast. The sourceClient is only sent for
// SAY* and RING commands.
func (s *Server) multicast(sessionIDs []int, msg string, ignore map[int]bool, sourceClient *Client, flag, notFlag string) {
	if ignore == nil {
		ignore = map[int]bool{}
	}
	var static []*Client
	for _, sessionID := range sessionIDs {
		client := s.clientFromSession(sessionID)
		if !client.loggedIn {
			continue
		}
		if ignore[sessionID] {
			continue
		}
		if sourceClient != nil && client.ignored[sourceClient.userID] {
			continue
		}
		if flag != "" && !client.compat[flag] { // send to users with compat flag
			continue
		}
		if notFlag != "" && client.compat[notFlag] { // send to users without compat flag
			continue
		}
		if client.static {
			static = append(static, client)
		} else {
			client.Send(msg)
		}
	}
	// this is so static clients don't respond before other people even receive the message
	for _, client := range static {
		client.Send(msg)
	}
}

// broadcast mirrors DataHandler.broadcast. The sourceClient is only sent for
// SAY* and RING commands.
func (s *Server) broadcast(msg, chanName string, ignore map[int]bool, sourceClient *Client, flag, notFlag string) {
	if ignore == nil {
		ignore = map[int]bool{}
	}
	if _, ok := s.channels[chanName]; !ok {
		sessionIDs := make([]int, 0, len(s.clients))
		for sessionID := range s.clients {
			sessionIDs = append(sessionIDs, sessionID)
		}
		s.multicast(sessionIDs, msg, ignore, sourceClient, flag, notFlag)
		return
	}
	channel := s.channels[chanName]
	sessionIDs := make([]int, 0, len(channel.users))
	for sessionID := range channel.users {
		sessionIDs = append(sessionIDs, sessionID)
	}
	s.multicast(sessionIDs, msg, ignore, sourceClient, flag, notFlag)
}

// broadcastBattle mirrors DataHandler.broadcast_battle. The sourceClient is
// only sent for SAY* and RING commands.
func (s *Server) broadcastBattle(msg string, battleID int, ignore map[int]bool, sourceClient *Client, flag, notFlag string) {
	if ignore == nil {
		ignore = map[int]bool{}
	}
	battle, ok := s.battles[battleID]
	if !ok {
		return
	}
	sessionIDs := make([]int, 0, len(battle.users))
	for sessionID := range battle.users {
		sessionIDs = append(sessionIDs, sessionID)
	}
	s.multicast(sessionIDs, msg, ignore, sourceClient, flag, notFlag)
}

// adminBroadcast mirrors DataHandler.admin_broadcast.
func (s *Server) adminBroadcast(msg string) {
	for username, client := range s.usernames {
		if username == "ChanServ" { // needed to allow "reload"
			continue
		}
		if client.accessLevels["admin"] {
			client.Send("SERVERMSG Admin broadcast: " + msg)
		}
	}
}

// getIPAddress mirrors DataHandler.get_ip_address.
func (s *Server) getIPAddress() string {
	conn, err := net.Dial("udp", "springrts.com:80")
	if err == nil {
		addr := conn.LocalAddr().(*net.UDPAddr).IP.String()
		conn.Close()
		return addr
	}
	if hostname, err := os.Hostname(); err == nil {
		if ips, err := net.LookupHost(hostname); err == nil && len(ips) > 0 {
			if ip := net.ParseIP(ips[0]); ip != nil {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

// detectIP mirrors DataHandler.detectIp.
func (s *Server) detectIP() {
	log.Println("Detecting local IP:")
	localAddr := s.getIPAddress()
	log.Println(localAddr)

	log.Println("Detecting online IP:")
	webAddr := localAddr
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get("https://springrts.com/lobby/getip.php"); err == nil {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if addr := strings.TrimSpace(string(data)); addr != "" {
			webAddr = addr
		}
		log.Println(webAddr)
	} else {
		log.Println("not online")
	}

	s.localIP = localAddr
	s.onlineIP = webAddr
}

// stats mirrors DataHandler.stats.
func (s *Server) stats() {
	log.Println(" -- STATS -- ")
	log.Println("Command counts (inbound):")
	for _, k := range sortedKeys(s.inboundCommandStats) {
		log.Printf(" %s %d", k, s.inboundCommandStats[k])
	}
	log.Println("Command counts (outbound):")
	for _, k := range sortedKeys(s.outboundCommandStats) {
		log.Printf(" %s %d", k, s.outboundCommandStats[k])
	}
	log.Printf("Number of logins: %d", s.nLoginStats)
	log.Printf("TLS logins: %d", s.tlsStats)
	log.Println("Agents:")
	for _, k := range sortedKeys(s.agentStats) {
		log.Printf(" %s  %d", k, s.agentStats[k])
	}
	log.Println("Flags sent:")
	for _, k := range sortedKeys(s.flagStats) {
		log.Printf(" %s %d", k, s.flagStats[k])
	}
	log.Println(" -- END STATS -- ")
}

// clientLoginStats mirrors DataHandler.client_LoginStats: record stats for
// this client's login.
func (s *Server) clientLoginStats(client *Client) {
	s.nLoginStats++
	if client.tls {
		s.tlsStats++
	}
	for flag := range client.compat {
		s.flagStats[flag]++
	}
	s.agentStats[client.agent]++
}

// reload mirrors DataHandler.reload. Go cannot reload compiled modules, so
// this re-reads the on-disk config files and re-derives the version and
// sayhook lists (the Go equivalent of the python importlib.reload calls).
func (s *Server) reload(client *Client) string {
	log.Printf("Reload initiated by <%s>", client.username)
	s.parseFiles()
	s.getServerVersion()
	sayHooks.updateLists()
	ret := "Reload successful"
	log.Println(ret)
	return ret
}

// md5B64 mirrors base64.b64encode(hashlib.md5(password.encode()).digest()).
func md5B64(password string) string {
	sum := md5.Sum([]byte(password))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// splitLines mirrors iterating a python file with line.rstrip('\r\n').
func splitLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		lines = append(lines, strings.TrimRight(l, "\r\n"))
	}
	return lines
}

// splitLinesTrim mirrors [l.strip() for l in f.readlines()].
func splitLinesTrim(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	return lines
}

// isDottedQuad mirrors proxy.replace('.', ”, 3).isdigit().
func isDottedQuad(s string) bool {
	dots := 0
	for _, r := range s {
		if r == '.' {
			dots++
		} else if r < '0' || r > '9' {
			return false
		}
	}
	return dots == 3
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mapKeys returns the keys of m in arbitrary order (equivalent to python's
// dict.copy() iteration; use when iterating while deleting).
func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// sortedIntKeys returns the keys of an int-keyed map in ascending order
// (deterministic iteration, Go maps are unordered).
func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// sortedStringKeys returns the keys of a string-keyed map in sorted order.
func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
