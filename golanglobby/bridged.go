package main

import "time"

// BridgedClient mirrors protocol/BridgedClient.py: a user present in an
// external location, who can speak in (some) channels via a bridging bot.
type BridgedClient struct {
	// db fields
	bridgedID        int
	externalID       string
	location         string
	externalUsername string
	lastBridged      time.Time

	// non-db fields
	username     string
	channels     map[string]bool
	bridgeUserID int // user_id of bridge bot
}

func newBridgedClient() *BridgedClient {
	return &BridgedClient{
		bridgedID:    -1,
		channels:     map[string]bool{},
		bridgeUserID: -1,
	}
}
