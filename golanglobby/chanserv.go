package main

import (
	"io"
	"log"
	"net"
	"time"
)

// noopConn is a net.Conn that accepts and discards all writes. It gives the
// in-memory ChanServ client the socket interface that Client methods expect
// (python's ChanServClient likewise has no real socket).
type noopConn struct{}

func (noopConn) Read(b []byte) (int, error)    { return 0, io.EOF }
func (noopConn) Write(b []byte) (int, error)   { return len(b), nil }
func (noopConn) Close() error                  { return nil }
func (noopConn) LocalAddr() net.Addr           { return &net.IPAddr{IP: net.ParseIP("127.0.0.1")} }
func (noopConn) RemoteAddr() net.Addr          { return &net.IPAddr{IP: net.ParseIP("127.0.0.1")} }
func (noopConn) SetDeadline(t time.Time) error { return nil }
func (noopConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (noopConn) SetWriteDeadline(t time.Time) error { return nil }

// ChanServ mirrors ChanServ.py's ChanServClient: the in-memory "ChanServ"
// user that acts as the issuer for server-side channel moderation. It embeds
// *Client so it can be used anywhere an online user reference is expected.
// Command handling (HandleCommand etc.) arrives with the full port.
type ChanServ struct {
	*Client
}

// newChanServ mirrors ChanServClient.__init__.
func newChanServ(root *Server, address net.Addr, sessionID int) *ChanServ {
	c := newClient(address, sessionID)
	c.accessLevels = map[string]bool{"admin": true, "mod": true, "user": true, "everyone": true}
	c.loggedIn = true
	c.bot = true
	c.userID = -1
	c.static = true
	c.username = "ChanServ"
	c.password = "ChanServ"
	c.agent = "ChanServ"
	c.conn = noopConn{}
	root.usernames[c.username] = c
	root.clients[sessionID] = c
	root.protocol.calcStatus(c, c.status)
	log.Printf("[%d] <%s> logged in (access=ChanServ)", sessionID, c.username)
	return &ChanServ{Client: c}
}

// handleProtocolCommand mirrors Client.HandleProtocolCommand: feed a
// protocol command line into the protocol handler.
func (cs *ChanServ) handleProtocolCommand(cmd string) {
	if len(cmd) < 1 {
		return
	}
	// runs as a state section: at startup this is called from init,
	// outside of any other section (nesting is handled by muDepth).
	server.stateLock()
	server.protocol.handle(cs.Client, cmd)
	server.stateUnlock()
}
