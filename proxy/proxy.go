package proxy

import (
	"bufio"
	"context"
	"fmt"
	dnstype "github.com/miekg/dns"
	"github.com/xvzc/SpoofDPI/dns/resolver"
	"golang.org/x/exp/maps"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xvzc/SpoofDPI/dns"
	"github.com/xvzc/SpoofDPI/packet"
	"github.com/xvzc/SpoofDPI/proxy/handler"
	"github.com/xvzc/SpoofDPI/util"
	"github.com/xvzc/SpoofDPI/util/log"
)

var domainList []string

const scopeProxy = "PROXY"

func init() {
	file, err := os.Open("blocked_domains.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domainList = append(domainList, domain)
		}
	}

	if err = scanner.Err(); err != nil {
		panic(err)
	}

}

type Proxy struct {
	addr           string
	port           int
	timeout        int
	resolver       *dns.Dns
	windowSize     int
	enableDoh      bool
	allowedPattern []*regexp.Regexp
	currentDns     string
	vpnPattern     []*regexp.Regexp
}

type Handler interface {
	Serve(ctx context.Context, lConn *net.TCPConn, pkt *packet.HttpRequest, ip string)
}

func New(config *util.Config) *Proxy {
	return &Proxy{
		addr:           config.Addr,
		port:           config.Port,
		timeout:        config.Timeout,
		windowSize:     config.WindowSize,
		enableDoh:      config.EnableDoh,
		allowedPattern: config.AllowedPatterns,
		currentDns:     config.CurrentDNS,
		vpnPattern:     config.VPNPatterns,
		resolver:       dns.NewDns(config),
	}
}

func (pxy *Proxy) Start(ctx context.Context) {
	ctx = util.GetCtxWithScope(ctx, scopeProxy)
	logger := log.GetCtxLogger(ctx)

	mu := sync.Mutex{}
	vpnCache := make(map[string][]net.IPAddr)
	vpnResolver := resolver.NewGeneralResolver(fmt.Sprintf("%s:53", pxy.currentDns))
	tick := time.Tick(30 * time.Minute)
	go func() {
		for range tick {
			logger.Warn().Msgf("clearing vpn dns cache")
			mu.Lock()
			maps.Clear(vpnCache)
			mu.Unlock()
		}
	}()

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(pxy.addr), Port: pxy.port})
	if err != nil {
		logger.Fatal().Msgf("error creating listener: %s", err)
		os.Exit(1)
	}

	if pxy.timeout > 0 {
		logger.Info().Msgf("connection timeout is set to %d ms", pxy.timeout)
	}

	logger.Info().Msgf("created a listener on port %d", pxy.port)
	if len(pxy.allowedPattern) > 0 {
		logger.Info().Msgf("number of white-listed pattern: %d", len(pxy.allowedPattern))
	}

	if len(pxy.vpnPattern) > 0 {
		logger.Info().Msgf("number of vpn pattern: %d", len(pxy.vpnPattern))
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Fatal().Msgf("error accepting connection: %s", err)
			continue
		}

		go func() {
			ctx = util.GetCtxWithTraceId(ctx)
			logger = log.GetCtxLogger(ctx)

			pkt, err := packet.ReadHttpRequest(conn)
			if err != nil {
				logger.Debug().Msgf("error while parsing request: %s", err)
				conn.Close()
				return
			}

			// resolve vpn addresses
			if len(pxy.vpnPattern) > 0 && pxy.vpnPatternMatches([]byte(pkt.Domain())) {
				mu.Lock()
				ip, exists := vpnCache[pkt.Domain()]
				mu.Unlock()
				if !exists {
					logger.Warn().Msgf("started custom vpn resolver, domain: %s", pkt.Domain())
					ip, err = vpnResolver.Resolve(ctx, pkt.Domain(), []uint16{dnstype.TypeAAAA, dnstype.TypeA})
					if err != nil {
						logger.Error().Msgf("error resolving custom domain: %s", err)
						conn.Close()
						return
					}
					if ip == nil {
						logger.Error().Msgf("error resolving custom domain: %s with dns:%s: no ip found", pkt.Domain(), pxy.currentDns)
						conn.Close()
						return
					}
					mu.Lock()
					vpnCache[pkt.Domain()] = ip
					mu.Unlock()
				} else {
					logger.Warn().Msgf("ip cache hit for domain: %s", pkt.Domain())
				}

				pxy.handleHttps(ctx, conn.(*net.TCPConn), false, pkt, ip[0].String())
				return
			}

			// blocking advertising domains
			for _, domain := range domainList {
				if strings.Contains(pkt.Domain(), domain) {
					logger.Warn().Msgf("blocked domain: %s", pkt.Domain())
					conn.Write([]byte(pkt.Version() + " 502 Bad Gateway\r\n\r\n"))
					conn.Close()
					return
				}
			}

			logger.Debug().Msgf("request from %s\n\n%s", conn.RemoteAddr(), pkt.Raw())

			pkt.Tidy()

			logger.Debug().Msgf("request from %s\n\n%s", conn.RemoteAddr(), string(pkt.Raw()))

			if !pkt.IsValidMethod() {
				logger.Debug().Msgf("unsupported method: %s", pkt.Method())
				conn.Close()
				return
			}

			matched := pxy.patternMatches([]byte(pkt.Domain()))
			useSystemDns := !matched

			ip, err := pxy.resolver.ResolveHost(ctx, pkt.Domain(), pxy.enableDoh, useSystemDns)
			if err != nil {
				logger.Debug().Msgf("error while dns lookup: %s %s", pkt.Domain(), err)
				conn.Write([]byte(pkt.Version() + " 502 Bad Gateway\r\n\r\n"))
				conn.Close()
				return
			}

			// Avoid recursively querying self
			if pkt.Port() == strconv.Itoa(pxy.port) && isLoopedRequest(ctx, net.ParseIP(ip)) {
				logger.Error().Msg("looped request has been detected. aborting.")
				conn.Close()
				return
			}

			var h Handler
			if pkt.IsConnectMethod() {
				h = handler.NewHttpsHandler(pxy.timeout, pxy.windowSize, pxy.allowedPattern, matched)
			} else {
				h = handler.NewHttpHandler(pxy.timeout)
			}

			h.Serve(ctx, conn.(*net.TCPConn), pkt, ip)
		}()
	}
}

func (pxy *Proxy) patternMatches(bytes []byte) bool {
	if pxy.allowedPattern == nil {
		return true
	}

	for _, pattern := range pxy.allowedPattern {
		if pattern.Match(bytes) {
			return true
		}
	}

	return false
}

func (pxy *Proxy) vpnPatternMatches(bytes []byte) bool {
	if pxy.vpnPattern == nil {
		return true
	}

	for _, pattern := range pxy.vpnPattern {
		if pattern.Match(bytes) {
			return true
		}
	}

	return false
}

func isLoopedRequest(ctx context.Context, ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	logger := log.GetCtxLogger(ctx)

	// Get list of available addresses
	// See `ip -4 addr show`
	addr, err := net.InterfaceAddrs() // needs AF_NETLINK on linux
	if err != nil {
		logger.Error().Msgf("error while getting addresses of our network interfaces: %s", err)
		return false
	}

	for _, addr := range addr {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(ip) {
				return true
			}
		}
	}

	return false
}
