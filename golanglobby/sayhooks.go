package main

import (
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SayHooks mirrors SayHooks.py.
type SayHooks struct {
	badWords map[string]string // lowercased word -> replacement
	badSites []string
	badNicks map[string]bool
}

var sayHooks = &SayHooks{
	badWords: map[string]string{},
	badNicks: map[string]bool{},
}

// updateLists reloads bad_words.txt, bad_sites.txt and bad_nicks.txt.
func (sh *SayHooks) updateLists() {
	sh.loadBadWords()
	sh.loadBadSites()
	sh.loadBadNicks()
}

func (sh *SayHooks) loadBadWords() {
	words := map[string]string{}
	data, err := os.ReadFile("bad_words.txt")
	if err != nil {
		log.Printf("Error parsing profanity list: %s", err)
		sh.badWords = words
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, " ") {
			words[strings.ToLower(line)] = "***"
		} else {
			parts := strings.SplitN(line, " ", 2)
			words[strings.ToLower(parts[0])] = parts[1]
		}
	}
	sh.badWords = words
}

func (sh *SayHooks) loadBadSites() {
	sites := []string{}
	data, err := os.ReadFile("bad_sites.txt")
	if err != nil {
		log.Printf("Error parsing shock site list: %s", err)
		sh.badSites = sites
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		found := false
		for _, s := range sites {
			if s == line {
				found = true
				break
			}
		}
		if found {
			log.Printf("duplicate line in bad_sites.txt: %s", line)
		} else {
			sites = append(sites, line)
		}
	}
	sh.badSites = sites
}

func (sh *SayHooks) loadBadNicks() {
	nicks := map[string]bool{}
	data, err := os.ReadFile("bad_nicks.txt")
	if err != nil {
		log.Printf("Error parsing bad nick list: %s", err)
		sh.badNicks = nicks
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		nicks[line] = true
	}
	sh.badNicks = nicks
}

// processWord censors a single word, preserving its uppercase state.
func (sh *SayHooks) processWord(word string) string {
	uppercase := word == strings.ToUpper(word)
	if repl, ok := sh.badWords[strings.ToLower(word)]; ok {
		word = repl
	}
	if uppercase {
		word = strings.ToUpper(word)
	}
	return word
}

// nastyWordCensor reports whether msg contains no bad words (true = clean).
func (sh *SayHooks) nastyWordCensor(msg string) bool {
	msg = strings.ToLower(msg)
	for word := range sh.badWords {
		if strings.Contains(msg, word) {
			return false
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// wordCensor replaces bad words inside msg, tokenizing on non-alnum runs.
func (sh *SayHooks) wordCensor(msg string) string {
	words := []string{}
	word := ""
	letters := true
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if isASCIIAlnum(c) == letters {
			word += string(c)
		} else {
			letters = !letters
			words = append(words, word)
			word = string(c)
		}
	}
	words = append(words, word)
	var b strings.Builder
	for _, w := range words {
		b.WriteString(sh.processWord(w))
	}
	return b.String()
}

// siteCensor returns (msg, true) when clean, ("", false) when a bad site is
// found (Python returns None in that case).
func (sh *SayHooks) siteCensor(msg string) (string, bool) {
	var testmsg1, testmsg2 strings.Builder
	for _, r := range msg {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r) {
			testmsg1.WriteString(string(r))
			testmsg2.WriteString(string(r))
		} else if r == '.' || r == '/' || r == '%' {
			testmsg2.WriteString(string(r))
		}
	}
	t1 := testmsg1.String()
	t2 := testmsg2.String()
	for _, site := range sh.badSites {
		if strings.Contains(msg, site) || strings.Contains(t1, site) || strings.Contains(t2, site) {
			return "", false
		}
	}
	return msg, true
}

// spamRec records msg in the client's last-said history for chan.
func (sh *SayHooks) spamRec(client *Client, chanName, msg string) {
	now := strconv.FormatFloat(float64(time.Now().UnixNano())/1e9, 'f', -1, 64)
	said, ok := client.lastSaid[chanName]
	if !ok {
		client.lastSaid[chanName] = map[string][]string{now: {msg}}
		return
	}
	if _, ok := said[now]; !ok {
		said[now] = []string{msg}
	} else {
		said[now] = append(said[now], msg)
	}
}

// spamEnum scores the client's messages in the last five seconds; bonus > 7 is spam.
func (sh *SayHooks) spamEnum(client *Client, chanName string) bool {
	said, ok := client.lastSaid[chanName]
	if !ok {
		return false
	}
	now := float64(time.Now().UnixNano()) / 1e9
	bonus := 0.0
	var already []string
	times := []float64{now}
	for when, msgs := range said {
		t, err := strconv.ParseFloat(when, 64)
		if err != nil {
			continue
		}
		if t > now-5 {
			for _, message := range msgs {
				times = append(times, t)
				count := 0
				for _, a := range already {
					if a == message {
						count++
					}
				}
				if count > 0 {
					bonus += 2 * float64(count) // repeated message
				}
				if utf8.RuneCountInString(message) > 50 {
					bonus += math.Min(float64(utf8.RuneCountInString(message)), 200) * 0.01 // long message
				}
				bonus += 1 // something was said
				already = append(already, message)
			}
		} else {
			delete(said, when)
		}
	}
	sort.Float64s(times)
	lastTime := 0.0
	hasLast := false
	for _, t := range times {
		if hasLast {
			diff := t - lastTime
			if diff < 1 {
				bonus += (1 - diff) * 1.5
			}
		}
		lastTime = t
		hasLast = true
	}
	return bonus > 7
}

// hookSay applies antispam to chat messages (Python hook_SAY).
func (sh *SayHooks) hookSay(client *Client, channel *Channel, msg string) string {
	if channel.isMuted(client) {
		return msg // client is muted, no use doing anything else
	}
	if channel.antispam && !channel.isOp(client) { // don't apply antispam to ops
		sh.spamRec(client, channel.name, msg)
		expires := time.Now().Add(5 * time.Minute)
		if sh.spamEnum(client, channel.name) {
			d := 5 * time.Minute
			channel.muteUser(server.ChanServ.Client, client, expires, "spamming", &d)
		}
	}
	return msg
}

// hookOpenBattle censors a battle title (Python hook_OPENBATTLE).
// ok is false when a bad site was found (Python returned None there, which
// crashed the .strip() at the call site; Go callers must handle ok == false).
func (sh *SayHooks) hookOpenBattle(client *Client, title string) (string, bool) {
	title = sh.wordCensor(title)
	title, ok := sh.siteCensor(title)
	return title, ok
}

// isNasty reports whether msg contains a bad nick (Python isNasty).
func (sh *SayHooks) isNasty(msg string) bool {
	msg = strings.ToLower(msg)
	cleaned := strings.NewReplacer("[", "", "]", "", "_", "").Replace(msg)
	for word := range sh.badNicks {
		if strings.Contains(msg, word) {
			return true
		}
		if strings.Contains(cleaned, word) {
			return true
		}
	}
	return false
}
