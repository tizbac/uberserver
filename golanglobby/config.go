package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port             int
	NATPort          int
	LogFileName      string
	Sighup           bool
	MinSpringVersion string
	SQLURL           string
	Censor           bool
	AgreementFile    string
	TrustedProxyFile string
	CertFile         string
	KeyFile          string
	DisableSignupURL string
	Redirect         string
}

// EffectiveNATPort returns the NAT port: the explicit -n value, or Port+1
// (mirrors DataHandler, where natport defaults to port+1).
func (c *Config) EffectiveNATPort() int {
	if c.NATPort != 0 {
		return c.NATPort
	}
	return c.Port + 1
}

func NewConfig() *Config {
	return &Config{
		Port:             8200,
		LogFileName:      "server.log",
		MinSpringVersion: "*",
		SQLURL:           "sqlite:///server.db",
		Censor:           true,
		CertFile:         "server.crt",
		KeyFile:          "server.key",
	}
}

func (c *Config) ParseArgv(argv []string) {
	args := map[string][]string{}
	mainarg := "ignoreme"

	tempargv := append([]string{}, argv...)
	for len(tempargv) > 0 {
		arg := tempargv[0]
		tempargv = tempargv[1:]
		if strings.HasPrefix(arg, "-") {
			mainarg = strings.ToLower(strings.TrimLeft(arg, "-"))

			if mainarg == "g" || mainarg == "loadargs" {
				name := tempargv[0]
				data, err := os.ReadFile(name)
				if err == nil {
					lines := strings.Split(string(data), "\n")
					tempargv = append(strings.Split(strings.Join(lines, " "), " "), tempargv...)
				}
			}

			args[mainarg] = []string{}
		} else {
			args[mainarg] = append(args[mainarg], arg)
		}
	}
	delete(args, "ignoreme")

	for arg, argp := range args {
		if len(argp) == 0 {
			continue
		}
		switch {
		case arg == "r" || arg == "redirect":
			c.Redirect = argp[0]
		case arg == "h" || arg == "help":
			c.ShowHelp()
		case arg == "p" || arg == "port":
			if v, err := strconv.Atoi(argp[0]); err == nil {
				c.Port = v
			} else {
				fmt.Println("Invalid port specification")
			}
		case arg == "n" || arg == "natport":
			if v, err := strconv.Atoi(argp[0]); err == nil {
				c.NATPort = v
			} else {
				fmt.Println("Invalid NAT port specification")
			}
		case arg == "o" || arg == "output":
			c.LogFileName = argp[0]
		case arg == "u" || arg == "sighup":
			c.Sighup = true
		case arg == "v" || arg == "min_spring_version":
			c.MinSpringVersion = argp[0]
		case arg == "s" || arg == "sqlurl":
			c.SQLURL = argp[0]
		case arg == "c" || arg == "no-censor":
			c.Censor = false
		case arg == "a" || arg == "agreement":
			c.AgreementFile = argp[0]
		case arg == "proxies":
			if f, err := os.Open(argp[0]); err == nil {
				c.TrustedProxyFile = argp[0]
				f.Close()
			} else {
				fmt.Println("Error opening trusted proxy file.")
				c.TrustedProxyFile = ""
			}
		case arg == "cert":
			c.CertFile = argp[0]
		case arg == "key":
			c.KeyFile = argp[0]
		case arg == "ds":
			c.DisableSignupURL = argp[0]
		}
	}
}

func (c *Config) ShowHelp() {
	fmt.Print(`Usage: golanglobby [OPTIONS]...
Starts uberserver.

Options:
  -h, --help
      { Displays this screen then exits }
  -p, --port number
      { Server will host on this port (default is 8200) }
  -n, --natport number
      { Server will use this port for NAT transversal (default is 8201) }
  -g, --loadargs filename
      { Reads additional command-line arguments from file }
  -o, --output /path/to/file.log
      { Writes console output to file (for logging) }
  -u, --sighup
      { Reload the server on SIGHUP (if SIGHUP is supported by OS) }
  -v, --min_spring_version version
      { Sets latest Spring version to this string. Defaults to "*" }
  -s, --sqlurl SQLURL
      { Uses SQL database at the specified sqlurl for user, channel, and ban storage. }
  --cert, --cert certificate.crt (PEM)
      Pem file with one or more certificate to make full trust chain
  --key, --key key.key (PEM)
      Pem file with private key of last certificate of trust chain
  -c, --no-censor
      { Disables censoring of #main, #newbies, and usernames (default is to censor) }
  --proxies /path/to/proxies.txt
     { Path to proxies.txt, for trusting proxies to pass real IP through local IP }
   -a --agreement /path/to/agreement.txt
     { sets the pat to the agreement file which is sent to a client registering at the server }
   -r --redirect "hostname/ip port"
     { redirects connecting clients to the given ip and port
   -ds Message
     Forbid lobby signup with specified url
`)
	os.Exit(0)
}
