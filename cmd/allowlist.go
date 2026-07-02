package cmd

import (
	"fmt"
	"net"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
)

type cliConfigAllowlist struct {
	Enabled           bool     `mapstructure:"enabled"`
	VMIDs             []string `mapstructure:"vmIds"`
	VMNames           []string `mapstructure:"vmNames"`
	MACs              []string `mapstructure:"macs"`
	IPs               []string `mapstructure:"ips"`
	CIDRs             []string `mapstructure:"cidrs"`
	Rules             []string `mapstructure:"rules"`
	Domains           []string `mapstructure:"domains"`
	LogSuppressed     *bool    `mapstructure:"logSuppressed"`
	WebhookSuppressed bool     `mapstructure:"webhookSuppressed"`
}

type allowlist struct {
	vmIDs             map[string]struct{}
	vmNames           map[string]struct{}
	macs              map[string]struct{}
	ips               map[string]struct{}
	cidrs             []*net.IPNet
	rules             map[string]struct{}
	domains           map[string]struct{}
	logSuppressed     bool
	webhookSuppressed bool
}

type allowlistMatch struct {
	Reason string
	Value  string
}

func newAllowlist(config cliConfigAllowlist) (*allowlist, error) {
	if !config.Enabled {
		return nil, nil
	}
	logSuppressed := true
	if config.LogSuppressed != nil {
		logSuppressed = *config.LogSuppressed
	}
	a := &allowlist{
		vmIDs:             makeStringSet(config.VMIDs),
		vmNames:           makeStringSet(config.VMNames),
		macs:              make(map[string]struct{}),
		ips:               make(map[string]struct{}),
		rules:             makeStringSet(config.Rules),
		domains:           make(map[string]struct{}),
		logSuppressed:     logSuppressed,
		webhookSuppressed: config.WebhookSuppressed,
	}
	for _, raw := range config.MACs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		mac := normalizeMAC(raw)
		if _, err := net.ParseMAC(mac); err != nil {
			return nil, fmt.Errorf("invalid allowlist mac %q: %w", raw, err)
		}
		a.macs[mac] = struct{}{}
	}
	for _, raw := range config.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if _, ipNet, err := net.ParseCIDR(raw); err == nil {
				a.cidrs = append(a.cidrs, ipNet)
			} else {
				return nil, fmt.Errorf("invalid allowlist ip/cidr %q: %w", raw, err)
			}
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid allowlist ip %q", raw)
		}
		a.ips[ip.String()] = struct{}{}
	}
	for _, raw := range config.CIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist cidr %q: %w", raw, err)
		}
		a.cidrs = append(a.cidrs, ipNet)
	}
	for _, raw := range config.Domains {
		domain := normalizeDomain(raw)
		if domain != "" {
			a.domains[domain] = struct{}{}
		}
	}
	return a, nil
}

func (a *allowlist) Match(event alertEvent) (allowlistMatch, bool) {
	if a == nil {
		return allowlistMatch{}, false
	}
	if value := event.Meta["vm.id"]; value != "" {
		if _, ok := a.vmIDs[value]; ok {
			return allowlistMatch{Reason: "vm.id", Value: value}, true
		}
	}
	if value := event.Meta["vm.name"]; value != "" {
		if _, ok := a.vmNames[value]; ok {
			return allowlistMatch{Reason: "vm.name", Value: value}, true
		}
	}
	for _, field := range []string{"vm.mac", "l2.src", "l2.dst"} {
		if value := normalizeMAC(event.Meta[field]); value != "" {
			if _, ok := a.macs[value]; ok {
				return allowlistMatch{Reason: field, Value: value}, true
			}
		}
	}
	for _, ip := range eventIPs(event) {
		if _, ok := a.ips[ip.String()]; ok {
			return allowlistMatch{Reason: "ip", Value: ip.String()}, true
		}
		for _, ipNet := range a.cidrs {
			if ipNet.Contains(ip) {
				return allowlistMatch{Reason: "cidr", Value: ipNet.String()}, true
			}
		}
	}
	if _, ok := a.rules[event.Rule]; ok {
		return allowlistMatch{Reason: "rule", Value: event.Rule}, true
	}
	for _, domain := range eventDomains(event) {
		if matched := a.matchDomain(domain); matched != "" {
			return allowlistMatch{Reason: "domain", Value: matched}, true
		}
	}
	return allowlistMatch{}, false
}

func (a *allowlist) LogSuppressed() bool {
	return a != nil && a.logSuppressed
}

func (a *allowlist) WebhookSuppressed() bool {
	return a != nil && a.webhookSuppressed
}

func (a *allowlist) matchDomain(domain string) string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return ""
	}
	if _, ok := a.domains[domain]; ok {
		return domain
	}
	for allowed := range a.domains {
		if strings.HasSuffix(domain, "."+allowed) {
			return allowed
		}
	}
	return ""
}

func eventIPs(event alertEvent) []net.IP {
	var ips []net.IP
	if event.IP != nil {
		for _, key := range []string{"src", "dst"} {
			if ip := net.ParseIP(event.IP[key]); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if event.Meta != nil {
		if ip := net.ParseIP(event.Meta["vm.ip"]); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func eventDomains(event alertEvent) []string {
	props, ok := event.Props.(analyzer.CombinedPropMap)
	if !ok {
		return nil
	}
	var domains []string
	addDomain := func(v interface{}) {
		if domain, ok := v.(string); ok {
			if normalized := normalizeDomain(domain); normalized != "" {
				domains = append(domains, normalized)
			}
		}
	}
	addDomain(props.Get("tls", "req.sni"))
	addDomain(props.Get("quic", "req.sni"))
	addQuestionDomains := func(v interface{}) {
		switch questions := v.(type) {
		case []analyzer.PropMap:
			for _, question := range questions {
				addDomain(question["name"])
			}
		case []interface{}:
			for _, question := range questions {
				switch q := question.(type) {
				case analyzer.PropMap:
					addDomain(q["name"])
				case map[string]interface{}:
					addDomain(q["name"])
				}
			}
		}
	}
	addQuestionDomains(props.Get("dns", "questions"))
	addQuestionDomains(props.Get("dns", "req.questions"))
	return domains
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	value = strings.TrimPrefix(value, "*.")
	return value
}
