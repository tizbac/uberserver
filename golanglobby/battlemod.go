package main

// battlemod.go — battle modification commands, mirroring protocol/Protocol.py
// in_BATTLEHOSTMSG ... in_REMOVEBOT.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// int32parse mirrors Protocol.int32: base-10 parse with 32-bit signed range check.
func int32parse(s string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if v > 2147483647 || v < -2147483648 {
		return 0, fmt.Errorf("overflow")
	}
	return v, nil
}

// uint32parse mirrors Protocol.uint32 (note Python's off-by-one upper bound 2**32).
func uint32parse(s string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if v > 4294967296 || v < 0 {
		return 0, fmt.Errorf("overflow")
	}
	return v, nil
}

// updateBattleInfoLine mirrors the 'UPDATEBATTLEINFO %s %i %i %s %s' format used
// across the Python handlers.
func (b *Battle) updateBattleInfoLine() string {
	locked := 0
	if b.locked {
		locked = 1
	}
	return fmt.Sprintf("UPDATEBATTLEINFO %s %d %d %s %s", b.battleIDStr(), b.spectators, locked, nilStr(b.mapHash), b.mapName)
}

// inKickFromBattle mirrors Protocol.in_KICKFROMBATTLE.
func (p *Protocol) inKickFromBattle(c *Client, username string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	if user.accessLevels["mod"] {
		return
	}
	user.Send("FORCEQUITBATTLE " + c.username)
	p.inLeaveBattle(user)
}

// inSetScriptTags mirrors Protocol.in_SETSCRIPTTAGS: keys are stored as sent
// but broadcast lowercased, in first-seen order (Python dict order).
func (p *Protocol) inSetScriptTags(c *Client, scripttags string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		p.outFailed(c, "SETSCRIPTTAGS", "You are not allowed to change settings in this battle", true)
		return
	}
	tags := map[string]string{}
	var order []string
	for _, pair := range strings.Split(scripttags, "\t") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if _, exists := tags[kv[0]]; !exists {
			order = append(order, kv[0])
		}
		tags[kv[0]] = kv[1]
	}
	if len(order) == 0 {
		return
	}
	for key, val := range tags { // Python dict.update: merge, keep existing
		battle.scriptTags[key] = val
	}
	parts := make([]string, 0, len(order))
	for _, key := range order {
		parts = append(parts, strings.ToLower(key)+"="+tags[key])
	}
	server.broadcastBattle("SETSCRIPTTAGS "+strings.Join(parts, "\t"), battle.battleID, nil, nil, "", "")
}

// inRemoveScriptTags mirrors Protocol.in_REMOVESCRIPTTAGS. Python iterates a
// set (arbitrary order); we sort for deterministic output.
func (p *Protocol) inRemoveScriptTags(c *Client, tags string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		p.outFailed(c, "REMOVESCRIPTTAGS", "You are not allowed to change settings in this battle", true)
		return
	}
	seen := map[string]bool{}
	removed := []string{}
	for _, tag := range strings.Split(tags, " ") {
		if seen[tag] {
			continue
		}
		seen[tag] = true
		if _, ok := battle.scriptTags[tag]; !ok {
			continue
		}
		delete(battle.scriptTags, tag)
		removed = append(removed, tag)
	}
	if len(removed) == 0 {
		return
	}
	sort.Strings(removed)
	server.broadcastBattle("REMOVESCRIPTTAGS "+strings.Join(removed, " "), battle.battleID, nil, nil, "", "")
}

// inMyBattleStatus mirrors Protocol.in_MYBATTLESTATUS.
func (p *Protocol) inMyBattleStatus(c *Client, statusStr, teamcolorStr string) {
	battlestatus, err := int32parse(statusStr)
	if err != nil {
		p.outFailed(c, "MYBATTLESTATUS", fmt.Sprintf("invalid status: %s.", statusStr), true)
		return
	}
	if battlestatus < 0 {
		p.outFailed(c, "MYBATTLESTATUS", fmt.Sprintf("invalid status is below 0: %s. Please update your lobby!", statusStr), true)
		battlestatus += 2147483648
	}
	myteamcolor, err := int32parse(teamcolorStr)
	if err != nil {
		// Python raised NameError here (myteamcolor unbound); we report the raw input
		p.outFailed(c, "MYBATTLESTATUS", fmt.Sprintf("invalid teamcolor: %s.", teamcolorStr), true)
		return
	}
	battle := p.getCurrentBattle(c)
	if battle == nil {
		p.outFailed(c, "MYBATTLESTATUS", "not inside a battle", true)
		return
	}
	spectating := c.battleStatus["mode"] == "0"
	spectators := 0
	for sessionID := range battle.users {
		if u := server.clientFromSession(sessionID); u != nil && u.battleStatus["mode"] == "0" {
			spectators++
		}
	}
	s := p.dec2bin(battlestatus, 32)
	side, sync := s[4:8], s[8:10]
	mode := s[21:22]
	ally, id, ready := s[22:26], s[26:30], s[30:31]
	if spectating {
		if len(battle.users)-spectators >= battle.maxPlayers {
			mode = "0"
		} else if mode == "1" {
			spectators--
		}
	} else if mode == "0" {
		spectators++
	}
	oldStatus := battle.calcBattleStatus(c)
	oldColor := c.teamColor
	c.battleStatus["ready"] = ready
	c.battleStatus["id"] = id
	c.battleStatus["ally"] = ally
	c.battleStatus["mode"] = mode
	c.battleStatus["sync"] = sync
	c.battleStatus["side"] = side
	c.teamColor = myteamcolor
	oldSpecs := battle.spectators
	battle.spectators = spectators
	if oldSpecs != spectators {
		server.broadcast(battle.updateBattleInfoLine(), "", nil, nil, "", "")
	}
	newStatus := battle.calcBattleStatus(c)
	statusCmd := fmt.Sprintf("CLIENTBATTLESTATUS %s %s %d", c.username, newStatus, myteamcolor)
	if oldStatus == newStatus && c.teamColor == oldColor {
		c.Send(statusCmd)
		return
	}
	server.broadcastBattle(statusCmd, battle.battleID, nil, nil, "", "")
}

// inUpdateBattleInfo mirrors Protocol.in_UPDATEBATTLEINFO.
func (p *Protocol) inUpdateBattleInfo(c *Client, spectatorCount, locked, maphash, mapname string) {
	battle := p.getCurrentBattle(c)
	if battle == nil {
		return
	}
	if battle.host != c.sessionID {
		return
	}
	mh, err := int32parse(maphash)
	if err != nil {
		p.outServerMsg(c, fmt.Sprintf("UPDATEBATTLEINFO failed - Invalid map hash send: %s %s ", mapname, maphash), true)
		return
	}
	if mapname == "" || strings.Contains(mapname, "\t") {
		p.outServerMsg(c, fmt.Sprintf("UPDATEBATTLEINFO failed - invalid mapname send: %s", mapname), true)
		return
	}
	oldStr := battle.updateBattleInfoLine()
	l, err := strconv.Atoi(locked)
	if err != nil {
		l = 0
	}
	battle.locked = l != 0
	mhStr := strconv.Itoa(mh)
	battle.mapHash = &mhStr
	battle.mapName = mapname
	if oldStr != battle.updateBattleInfoLine() {
		server.broadcast(battle.updateBattleInfoLine(), "", nil, nil, "", "")
	}
}

// inRing mirrors Protocol.in_RING. Mods may ring anyone; other players may
// only ring battle members of a battle they host or are hosted in.
func (p *Protocol) inRing(c *Client, username string) {
	user := server.clientFromUsername(username)
	if user == nil {
		return
	}
	if c.currentBattle == nil {
		return
	}
	if !c.accessLevels["mod"] {
		battle := p.getCurrentBattle(c)
		if battle == nil {
			return
		}
		if battle.host != c.sessionID && battle.host != user.sessionID {
			return
		}
		if !battle.users[c.sessionID] {
			return
		}
	}
	if !p.isIgnored(user, c) {
		user.Send("RING " + c.username)
	}
}

// inAddStartRect mirrors Protocol.in_ADDSTARTRECT.
func (p *Protocol) inAddStartRect(c *Client, allyno, left, top, right, bottom string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	invalid := func() { p.outServerMsg(c, "invalid ADDSTARTRECT received", false) }
	ally, err := int32parse(allyno)
	if err != nil {
		invalid()
		return
	}
	l, err := uint32parse(left)
	if err != nil {
		invalid()
		return
	}
	t, err := uint32parse(top)
	if err != nil {
		invalid()
		return
	}
	r, err := uint32parse(right)
	if err != nil {
		invalid()
		return
	}
	b, err := uint32parse(bottom)
	if err != nil {
		invalid()
		return
	}
	battle.startRects[ally] = &StartRect{left: strconv.Itoa(l), top: strconv.Itoa(t), right: strconv.Itoa(r), bottom: strconv.Itoa(b)}
	server.broadcastBattle(fmt.Sprintf("ADDSTARTRECT %d %d %d %d %d", ally, l, t, r, b), battle.battleID, nil, nil, "", "")
}

// inRemoveStartRect mirrors Protocol.in_REMOVESTARTRECT.
func (p *Protocol) inRemoveStartRect(c *Client, allyno string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	ally, err := int32parse(allyno)
	if err != nil {
		return // Python crashed here (int32 called outside its try block)
	}
	if _, ok := battle.startRects[ally]; !ok {
		p.outServerMsg(c, fmt.Sprintf("invalid rect removed: %d", ally), true)
		return
	}
	delete(battle.startRects, ally)
	server.broadcastBattle(fmt.Sprintf("REMOVESTARTRECT %d", ally), battle.battleID, nil, nil, "", "")
}

// inDisableUnits mirrors Protocol.in_DISABLEUNITS.
func (p *Protocol) inDisableUnits(c *Client, units string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	disabled := []string{}
	for _, unit := range strings.Split(units, " ") {
		found := false
		for _, d := range battle.disabledUnits {
			if d == unit {
				found = true
				break
			}
		}
		if !found {
			battle.disabledUnits = append(battle.disabledUnits, unit)
			disabled = append(disabled, unit)
		}
	}
	if len(disabled) > 0 {
		server.broadcastBattle("DISABLEUNITS "+strings.Join(disabled, " "), battle.battleID, nil, nil, "", "")
	}
}

// inEnableUnits mirrors Protocol.in_ENABLEUNITS. Python raised NameError here
// (battle_id undefined) and died before broadcasting; we broadcast as intended.
func (p *Protocol) inEnableUnits(c *Client, units string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	enabled := []string{}
	for _, unit := range strings.Split(units, " ") {
		idx := -1
		for i, d := range battle.disabledUnits {
			if d == unit {
				idx = i
				break
			}
		}
		if idx >= 0 {
			battle.disabledUnits = append(battle.disabledUnits[:idx], battle.disabledUnits[idx+1:]...)
			enabled = append(enabled, unit)
		}
	}
	if len(enabled) > 0 {
		server.broadcastBattle("ENABLEUNITS "+strings.Join(enabled, " "), battle.battleID, nil, nil, "", "")
	}
}

// inEnableAllUnits mirrors Protocol.in_ENABLEALLUNITS.
func (p *Protocol) inEnableAllUnits(c *Client) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	battle.disabledUnits = []string{}
	server.broadcastBattle("ENABLEALLUNITS", battle.battleID, nil, nil, "", "")
}

// inHandicap mirrors Protocol.in_HANDICAP.
func (p *Protocol) inHandicap(c *Client, username, value string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	if !isDigits(value) {
		return
	}
	v, err := strconv.Atoi(value)
	if err != nil || v < 0 || v > 100 {
		return
	}
	user.battleStatus["handicap"] = p.dec2bin(v, 7)
	userBattle := p.getCurrentBattle(c)
	if userBattle == nil {
		return
	}
	server.broadcastBattle(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", username, userBattle.calcBattleStatus(user), pyStr(user.teamColor)), userBattle.battleID, nil, nil, "", "")
}

// inForceTeamNo mirrors Protocol.in_FORCETEAMNO.
func (p *Protocol) inForceTeamNo(c *Client, username, teamno string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	v, err := strconv.Atoi(teamno)
	if err != nil {
		return
	}
	user.battleStatus["id"] = p.dec2bin(v, 4)
	userBattle := p.getCurrentBattle(c)
	if userBattle == nil {
		return
	}
	server.broadcastBattle(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", username, userBattle.calcBattleStatus(user), pyStr(user.teamColor)), userBattle.battleID, nil, nil, "", "")
}

// inForceAllyNo mirrors Protocol.in_FORCEALLYNO.
func (p *Protocol) inForceAllyNo(c *Client, username, allyno string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	v, err := strconv.Atoi(allyno)
	if err != nil {
		return
	}
	user.battleStatus["ally"] = p.dec2bin(v, 4)
	userBattle := p.getCurrentBattle(c)
	if userBattle == nil {
		return
	}
	server.broadcastBattle(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", username, userBattle.calcBattleStatus(user), pyStr(user.teamColor)), userBattle.battleID, nil, nil, "", "")
}

// inForceTeamColor mirrors Protocol.in_FORCETEAMCOLOR. The raw string is
// stored, so a later MYBATTLESTATUS (int) always differs and re-broadcasts.
func (p *Protocol) inForceTeamColor(c *Client, username, teamcolor string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	user.teamColor = teamcolor
	userBattle := p.getCurrentBattle(c)
	if userBattle == nil {
		return
	}
	server.broadcastBattle(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", username, userBattle.calcBattleStatus(user), teamcolor), userBattle.battleID, nil, nil, "", "")
}

// inForceSpectatorMode mirrors Protocol.in_FORCESPECTATORMODE.
func (p *Protocol) inForceSpectatorMode(c *Client, username string) {
	battle := p.getCurrentBattle(c)
	if battle == nil || !battle.canChangeSettings(c) {
		return
	}
	user := server.clientFromUsername(username)
	if user == nil || !battle.users[user.sessionID] {
		return
	}
	if user.battleStatus["mode"] != "1" {
		return
	}
	userBattle := p.getCurrentBattle(user)
	if userBattle == nil {
		return
	}
	userBattle.spectators++
	user.battleStatus["mode"] = "0"
	server.broadcastBattle(fmt.Sprintf("CLIENTBATTLESTATUS %s %s %s", username, userBattle.calcBattleStatus(user), pyStr(user.teamColor)), userBattle.battleID, nil, nil, "", "")
	server.broadcast(userBattle.updateBattleInfoLine(), "", nil, nil, "", "")
}

// inAddBot mirrors Protocol.in_ADDBOT.
func (p *Protocol) inAddBot(c *Client, name, battlestatus, teamcolor, aidll string) {
	battle := p.getCurrentBattle(c)
	if battle == nil {
		p.outFailed(c, "ADDBOT", "Couldn't find battle", true)
		return
	}
	if _, ok := battle.bots[name]; ok {
		p.outFailed(c, "ADDBOT", "Bot already exists!", false)
		return
	}
	bot := &Bot{owner: c.username, battleStatus: battlestatus, teamColor: teamcolor, aidll: aidll}
	c.battleBots[name] = bot
	battle.bots[name] = bot
	server.broadcastBattle(fmt.Sprintf("ADDBOT %s %s %s %s %s %s", battle.battleIDStr(), name, c.username, battlestatus, teamcolor, aidll), battle.battleID, nil, nil, "", "")
}

// inUpdateBot mirrors Protocol.in_UPDATEBOT (owner or host only).
func (p *Protocol) inUpdateBot(c *Client, name, battlestatus, teamcolor string) {
	battle := p.getCurrentBattle(c)
	if battle == nil {
		p.outFailed(c, "UPDATEBOT", "Couldn't find battle", true)
		return
	}
	bot, ok := battle.bots[name]
	if !ok {
		return
	}
	if c.username == bot.owner || c.sessionID == battle.host {
		bot.battleStatus = battlestatus
		bot.teamColor = teamcolor
		server.broadcastBattle(fmt.Sprintf("UPDATEBOT %s %s %s %s", battle.battleIDStr(), name, battlestatus, teamcolor), battle.battleID, nil, nil, "", "")
	}
}

// inRemoveBot mirrors Protocol.in_REMOVEBOT (owner or host only).
func (p *Protocol) inRemoveBot(c *Client, name string) {
	battle := p.getCurrentBattle(c)
	if battle == nil {
		p.outFailed(c, "REMOVEBOT", "Couldn't find battle", true)
		return
	}
	bot, ok := battle.bots[name]
	if !ok {
		return
	}
	if c.username == bot.owner || c.sessionID == battle.host {
		if owner := server.clientFromUsername(bot.owner); owner != nil {
			delete(owner.battleBots, name)
		}
		delete(battle.bots, name)
		server.broadcastBattle(fmt.Sprintf("REMOVEBOT %s %s", battle.battleIDStr(), name), battle.battleID, nil, nil, "", "")
	}
}
