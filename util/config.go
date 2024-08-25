package util

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
)

type Config struct {
	Addr            string
	Port            int
	DnsAddr         string
	DnsPort         int
	EnableDoh       bool
	Debug           bool
	NoBanner        bool
	SystemProxy     bool
	Timeout         int
	WindowSize      int
	AllowedPatterns []*regexp.Regexp
	CurrentDNS      string
	VPNPatterns     []*regexp.Regexp
}

var config *Config

func GetConfig() *Config {
	if config == nil {
		config = new(Config)
	}
	return config
}

func (c *Config) Load(args *Args) {
	c.Addr = args.Addr
	c.Port = args.Port
	c.DnsAddr = args.DnsAddr
	c.DnsPort = args.DnsPort
	c.Debug = args.Debug
	c.EnableDoh = args.EnableDoh
	c.NoBanner = args.NoBanner
	c.SystemProxy = args.SystemProxy
	c.Timeout = args.Timeout
	c.AllowedPatterns = parseAllowedPattern(args.AllowedPattern)
	c.VPNPatterns = parseAllowedPattern(args.VPNPattern)
	c.WindowSize = args.WindowSize

	currentDns, err := getCurrentDNSServer()
	if err != nil {
		panic(err)
	}
	c.CurrentDNS = currentDns
}

func parseAllowedPattern(patterns StringArray) []*regexp.Regexp {
	var allowedPatterns []*regexp.Regexp

	for _, pattern := range patterns {
		allowedPatterns = append(allowedPatterns, regexp.MustCompile(pattern))
	}

	return allowedPatterns
}

func PrintColoredBanner() {
	cyan := putils.LettersFromStringWithStyle("Spoof", pterm.NewStyle(pterm.FgCyan))
	purple := putils.LettersFromStringWithStyle("DPI", pterm.NewStyle(pterm.FgLightMagenta))
	pterm.DefaultBigText.WithLetters(cyan, purple).Render()

	pterm.DefaultBulletList.WithItems([]pterm.BulletListItem{
		{Level: 0, Text: "SYSTEM     : " + fmt.Sprint(runtime.GOOS)},
		{Level: 0, Text: "ADDR       : " + fmt.Sprint(config.Addr)},
		{Level: 0, Text: "PORT       : " + fmt.Sprint(config.Port)},
		{Level: 0, Text: "DNS        : " + fmt.Sprint(config.DnsAddr)},
		{Level: 0, Text: "SYSTEM DNS : " + fmt.Sprint(config.CurrentDNS)},
		{Level: 0, Text: "DEBUG      : " + fmt.Sprint(config.Debug)},
	}).Render()
}

func PrintSimpleInfo() {
	fmt.Println("")
	fmt.Println("- ADDR    : ", config.Addr)
	fmt.Println("- PORT    : ", config.Port)
	fmt.Println("- DNS     : ", config.DnsAddr)
	fmt.Println("- DEBUG   : ", config.Debug)
	fmt.Println("")
}

func getCurrentDNSServer() (string, error) {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("scutil", "--dns")
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to run scutil command: %v", err)
		}

		var dnsServer string
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			if bytes.Contains(line, []byte("nameserver")) {
				fields := strings.Fields(string(line))
				if len(fields) > 1 {
					dnsServer = fields[2]
					break
				}
			}
		}
		if dnsServer == "" {
			return "", fmt.Errorf("DNS server not found")
		}
		return dnsServer, nil
	}
	return "", errors.New("OS not supported")
}
