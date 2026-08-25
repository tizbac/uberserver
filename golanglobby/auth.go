package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTimeCost    = 3
	argonMemoryCost  = 65536
	argonParallelism = 4
	argonKeyLength   = 32
	argonSaltLength  = 16
)

func b64nopad(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func b64nopadDecode(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }

// HashPassword produces a PHC-format argon2id hash, matching argon2-cffi
// PasswordHasher() defaults. passwordB64 is the BASE64(MD5(password)) string
// as sent by the client.
func HashPassword(passwordB64 string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(passwordB64), salt, argonTimeCost, argonMemoryCost, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemoryCost, argonTimeCost, argonParallelism, b64nopad(salt), b64nopad(key)), nil
}

// VerifyPassword checks passwordB64 against a stored hash, which may be a PHC
// argon2id string or (legacy) the raw base64(md5) password itself.
func VerifyPassword(stored, passwordB64 string) bool {
	if strings.HasPrefix(stored, "$argon2") {
		parts := strings.Split(stored, "$")
		if len(parts) != 6 {
			return false
		}
		var mem, timeCost, par int
		for _, p := range strings.Split(parts[3], ",") {
			switch {
			case strings.HasPrefix(p, "m="):
				mem, _ = strconv.Atoi(p[2:])
			case strings.HasPrefix(p, "t="):
				timeCost, _ = strconv.Atoi(p[2:])
			case strings.HasPrefix(p, "p="):
				par, _ = strconv.Atoi(p[2:])
			}
		}
		if mem <= 0 || timeCost <= 0 || par <= 0 {
			return false
		}
		salt, err := b64nopadDecode(parts[4])
		if err != nil {
			return false
		}
		want, err := b64nopadDecode(parts[5])
		if err != nil {
			return false
		}
		key := argon2.IDKey([]byte(passwordB64), salt, uint32(timeCost), uint32(mem), uint8(par), uint32(len(want)))
		return subtle.ConstantTimeCompare(key, want) == 1
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(passwordB64)) == 1
}
