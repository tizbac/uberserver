package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// maxClients mirrors twistedserver.py: RLIMIT_NOFILE / 2.
func maxClients() int {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil || rlim.Cur == 0 {
		return 1024
	}
	return int(rlim.Cur) / 2
}

// loopEvery mirrors twisted's task.LoopingCall: run f every d (the first
// invocation is after d, like LoopingCall). Each run is a state section.
func loopEvery(f func(), d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for range ticker.C {
		server.stateLock()
		f()
		server.stateUnlock()
	}
}

// acceptLoop mirrors twistedserver's ChatFactory: accept connections and
// handle each in its own goroutine.
func acceptLoop(ln net.Listener, max int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn, max)
	}
}

// handleConnection mirrors twistedserver's Chat.connectionMade /
// connectionLost: register the client, run its read loop, then clean up.
func handleConnection(conn net.Conn, max int) {
	server.stateLock()
	if len(server.clients) >= max {
		log.Printf("to many connections: %d > %d", len(server.clients), max)
		server.stateUnlock()
		conn.Write([]byte("DENIED to many connections, sorry!\n"))
		conn.Close()
		return
	}
	server.sessionID++
	client := newClient(conn.RemoteAddr(), server.sessionID)
	client.conn = conn
	server.clients[client.sessionID] = client
	server.protocol.newClient(client)
	server.stateUnlock()

	go client.timeoutLoop()
	client.readLoop()

	// connection lost
	reason := client.removeReason
	if reason == "" {
		reason = "connection lost"
	}
	server.stateLock()
	server.protocol.removeClient(client, reason)
	delete(server.clients, client.sessionID)
	server.stateUnlock()
	conn.Close()
}

func main() {
	cfg := NewConfig()
	cfg.ParseArgv(os.Args[1:])

	server = newServer(cfg)

	if cfg.Sighup {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				log.Println("Received SIGHUP.")
				if server.sighup {
					server.stateLock()
					server.reload(server.ChanServ.Client)
					server.stateUnlock()
				}
			}
		}()
	}

	if f, err := os.OpenFile(server.logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	} else {
		log.Printf("could not open log file %s: %s", server.logFilename, err)
	}

	log.Println("Starting uberserver...")

	// TODO(NAT): port NATServer.py; hole punching is unavailable until then
	// (python logs "Could not start NAT server - hole punching will be
	// unavailable." when the NAT port cannot be bound).
	log.Println("NAT server not yet ported - hole punching will be unavailable.")

	if err := server.init(); err != nil {
		log.Printf("init failed: %s", err)
		log.Println("Exception caught, exiting...")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", server.port))
	if err != nil {
		log.Fatalf("could not listen on port %d: %s", server.port, err)
	}
	fmt.Println("Started lobby server!")
	fmt.Println("Connect the lobby client to")
	fmt.Printf("  public:  %s:%d\n", server.onlineIP, server.port)
	fmt.Printf("  private: %s:%d\n", server.localIP, server.port)

	go acceptLoop(ln, maxClients())

	go loopEvery(func() { server.scheduledClean() }, 24*time.Hour)
	go loopEvery(func() { server.channelMuteBanTimeout() }, time.Second)
	go loopEvery(func() { server.decrementRecentRegistrations() }, 20*time.Minute)
	go loopEvery(func() { server.decrementRecentRenames() }, 7*24*time.Hour)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Server killed by keyboard interrupt.")

	server.stateLock()
	ln.Close()
	server.shutdown()
	server.stateUnlock()
}
