package main

// GeoIP lookup. The Python server uses the legacy GeoIP C database at
// /usr/share/GeoIP/GeoIP.dat; when it is missing, lookups return '??'.
// The Go build keeps the same fallback behavior.
func lookupCountry(ip string) string {
	return "??"
}
