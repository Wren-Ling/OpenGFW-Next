package cmd

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apernet/OpenGFW/ruleset"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type cliConfigIdentity struct {
	Inventory string                   `mapstructure:"inventory"`
	Entries   []identityEntry          `mapstructure:"entries"`
	Libvirt   cliConfigIdentityLibvirt `mapstructure:"libvirt"`
}

type cliConfigIdentityLibvirt struct {
	Enabled         bool          `mapstructure:"enabled"`
	URI             string        `mapstructure:"uri"`
	RefreshInterval time.Duration `mapstructure:"refreshInterval"`
}

type identityInventory struct {
	Entries []identityEntry `yaml:"entries"`
}

type identityEntry struct {
	ID         string            `yaml:"id" mapstructure:"id"`
	Name       string            `yaml:"name" mapstructure:"name"`
	Tenant     string            `yaml:"tenant" mapstructure:"tenant"`
	MACs       []string          `yaml:"macs" mapstructure:"macs"`
	IPs        []string          `yaml:"ips" mapstructure:"ips"`
	Interfaces []string          `yaml:"interfaces" mapstructure:"interfaces"`
	VLANs      []string          `yaml:"vlans" mapstructure:"vlans"`
	Labels     map[string]string `yaml:"labels" mapstructure:"labels"`
	Source     string            `yaml:"-" mapstructure:"-"`
}

type identityEnricher struct {
	staticEntries []compiledIdentityEntry
	entries       atomic.Value
	cancel        context.CancelFunc
	done          chan struct{}
}

type compiledIdentityEntry struct {
	Entry      identityEntry
	MACs       map[string]struct{}
	IPs        map[string]struct{}
	IPNets     []*net.IPNet
	Interfaces map[string]struct{}
	VLANs      map[string]struct{}
}

const (
	defaultLibvirtRefreshInterval = 5 * time.Minute
	libvirtCommandTimeout         = 15 * time.Second
)

func newIdentityEnricher(config cliConfigIdentity) (*identityEnricher, error) {
	entries := append([]identityEntry{}, config.Entries...)
	if config.Inventory != "" {
		inventoryEntries, err := loadIdentityInventory(config.Inventory)
		if err != nil {
			return nil, err
		}
		entries = append(entries, inventoryEntries...)
	}
	for i := range entries {
		if entries[i].Source == "" {
			entries[i].Source = "inventory"
		}
	}
	if len(entries) == 0 && !config.Libvirt.Enabled {
		return nil, nil
	}

	compiled := make([]compiledIdentityEntry, 0, len(entries))
	for _, entry := range entries {
		compiled = append(compiled, compileIdentityEntry(entry))
	}
	enricher := &identityEnricher{staticEntries: compiled}
	enricher.entries.Store(compiled)
	if config.Libvirt.Enabled {
		enricher.startLibvirtProvider(config.Libvirt, execCommandRunner)
	}
	return enricher, nil
}

func (e *identityEnricher) Close() {
	if e == nil || e.cancel == nil {
		return
	}
	e.cancel()
	<-e.done
}

func loadIdentityInventory(path string) ([]identityEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var inventory identityInventory
	if err := yaml.Unmarshal(data, &inventory); err == nil && inventory.Entries != nil {
		return inventory.Entries, nil
	}

	var entries []identityEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func compileIdentityEntry(entry identityEntry) compiledIdentityEntry {
	c := compiledIdentityEntry{
		Entry:      entry,
		MACs:       makeStringSet(normalizeStrings(entry.MACs, normalizeMAC)),
		IPs:        make(map[string]struct{}),
		Interfaces: makeStringSet(entry.Interfaces),
		VLANs:      makeStringSet(normalizeStrings(entry.VLANs, normalizeVLAN)),
	}
	for _, raw := range entry.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if _, ipNet, err := net.ParseCIDR(raw); err == nil {
				c.IPNets = append(c.IPNets, ipNet)
			}
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			c.IPs[ip.String()] = struct{}{}
		}
	}
	return c
}

func (e *identityEnricher) Enrich(info ruleset.StreamInfo) map[string]string {
	if e == nil {
		return nil
	}
	entries, _ := e.entries.Load().([]compiledIdentityEntry)
	for _, entry := range entries {
		if match, source, value := entry.Match(info); match {
			return entry.Metadata(source, value)
		}
	}
	return nil
}

func (e compiledIdentityEntry) Match(info ruleset.StreamInfo) (bool, string, string) {
	if !e.constraintsMatch(info.Meta) {
		return false, "", ""
	}
	if len(e.MACs) > 0 {
		srcMAC := normalizeMAC(info.Meta["l2.src"])
		if _, ok := e.MACs[srcMAC]; ok {
			return true, "l2.src", srcMAC
		}
		dstMAC := normalizeMAC(info.Meta["l2.dst"])
		if _, ok := e.MACs[dstMAC]; ok {
			return true, "l2.dst", dstMAC
		}
	}
	if e.matchIP(info.SrcIP) {
		return true, "ip.src", info.SrcIP.String()
	}
	if e.matchIP(info.DstIP) {
		return true, "ip.dst", info.DstIP.String()
	}
	return false, "", ""
}

func (e compiledIdentityEntry) constraintsMatch(meta map[string]string) bool {
	if len(e.Interfaces) > 0 {
		if _, ok := e.Interfaces[meta["capture.interface"]]; !ok {
			return false
		}
	}
	if len(e.VLANs) > 0 {
		if _, ok := e.VLANs[normalizeVLAN(meta["vlan.id"])]; !ok {
			return false
		}
	}
	return true
}

func (e compiledIdentityEntry) matchIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ipString := ip.String()
	if _, ok := e.IPs[ipString]; ok {
		return true
	}
	for _, ipNet := range e.IPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (e compiledIdentityEntry) Metadata(source, value string) map[string]string {
	identitySource := e.Entry.Source
	if identitySource == "" {
		identitySource = "inventory"
	}
	m := map[string]string{
		"identity.source": identitySource,
		"identity.match":  source,
		"identity.value":  value,
	}
	if e.Entry.ID != "" {
		m["vm.id"] = e.Entry.ID
	}
	if e.Entry.Name != "" {
		m["vm.name"] = e.Entry.Name
	}
	if e.Entry.Tenant != "" {
		m["vm.tenant"] = e.Entry.Tenant
	}
	if strings.HasPrefix(source, "l2.") && value != "" {
		m["vm.mac"] = value
	} else if mac, ok := singleSetValue(e.MACs); ok {
		m["vm.mac"] = mac
	}
	if strings.HasPrefix(source, "ip.") && value != "" {
		m["vm.ip"] = value
	}
	for k, v := range e.Entry.Labels {
		if strings.TrimSpace(k) == "" {
			continue
		}
		m["vm.label."+k] = v
	}
	return m
}

func (e *identityEnricher) startLibvirtProvider(config cliConfigIdentityLibvirt, runCommand commandRunner) {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = defaultLibvirtRefreshInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	provider := &libvirtInventoryProvider{
		uri:        config.URI,
		runCommand: runCommand,
	}
	go func() {
		defer close(e.done)
		e.refreshLibvirtInventory(ctx, provider)
		ticker := time.NewTicker(config.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.refreshLibvirtInventory(ctx, provider)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (e *identityEnricher) refreshLibvirtInventory(ctx context.Context, provider *libvirtInventoryProvider) {
	entries, err := provider.Load(ctx)
	if err != nil {
		if logger != nil {
			logger.Warn("failed to refresh libvirt identity inventory", zap.Error(err))
		}
		return
	}
	e.entries.Store(mergeIdentityEntries(e.staticEntries, entries))
	if logger != nil {
		logger.Debug("libvirt identity inventory refreshed", zap.Int("entries", len(entries)))
	}
}

func mergeIdentityEntries(staticEntries []compiledIdentityEntry, dynamicEntries []identityEntry) []compiledIdentityEntry {
	compiled := make([]compiledIdentityEntry, 0, len(staticEntries)+len(dynamicEntries))
	compiled = append(compiled, staticEntries...)
	for _, entry := range dynamicEntries {
		compiled = append(compiled, compileIdentityEntry(entry))
	}
	return compiled
}

type libvirtInventoryProvider struct {
	uri        string
	runCommand commandRunner
}

func (p *libvirtInventoryProvider) Load(ctx context.Context) ([]identityEntry, error) {
	if p.runCommand == nil {
		p.runCommand = execCommandRunner
	}
	names, err := p.domainNames(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]identityEntry, 0, len(names))
	for _, name := range names {
		rawXML, err := p.virsh(ctx, "dumpxml", name)
		if err != nil {
			return nil, fmt.Errorf("dumpxml %q: %w", name, err)
		}
		entry, ok, err := parseLibvirtDomainXML(rawXML, name)
		if err != nil {
			return nil, fmt.Errorf("parse domain XML %q: %w", name, err)
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (p *libvirtInventoryProvider) domainNames(ctx context.Context) ([]string, error) {
	output, err := p.virsh(ctx, "list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func (p *libvirtInventoryProvider) virsh(ctx context.Context, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, libvirtCommandTimeout)
	defer cancel()

	fullArgs := make([]string, 0, len(args)+2)
	if p.uri != "" {
		fullArgs = append(fullArgs, "--connect", p.uri)
	}
	fullArgs = append(fullArgs, args...)
	output, err := p.runCommand(commandCtx, "virsh", fullArgs...)
	if err != nil {
		return output, fmt.Errorf("virsh %s: %w: %s", strings.Join(fullArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type libvirtDomainXML struct {
	Name    string `xml:"name"`
	UUID    string `xml:"uuid"`
	Devices struct {
		Interfaces []struct {
			MAC struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
		} `xml:"interface"`
	} `xml:"devices"`
}

func parseLibvirtDomainXML(data []byte, fallbackName string) (identityEntry, bool, error) {
	var domain libvirtDomainXML
	if err := xml.Unmarshal(data, &domain); err != nil {
		return identityEntry{}, false, err
	}
	entry := identityEntry{
		ID:     strings.TrimSpace(domain.UUID),
		Name:   strings.TrimSpace(domain.Name),
		Source: "libvirt",
	}
	if entry.Name == "" {
		entry.Name = fallbackName
	}
	if entry.ID == "" {
		entry.ID = entry.Name
	}
	for _, iface := range domain.Devices.Interfaces {
		if mac := normalizeMAC(iface.MAC.Address); mac != "" {
			entry.MACs = append(entry.MACs, mac)
		}
	}
	if entry.Name == "" || len(entry.MACs) == 0 {
		return identityEntry{}, false, nil
	}
	return entry, true, nil
}

func singleSetValue(values map[string]struct{}) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	for value := range values {
		return value, true
	}
	return "", false
}

func makeStringSet(values []string) map[string]struct{} {
	m := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		m[value] = struct{}{}
	}
	return m
}

func normalizeStrings(values []string, normalize func(string) string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalize(value); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

func normalizeMAC(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if mac, err := net.ParseMAC(value); err == nil {
		return mac.String()
	}
	compact := strings.NewReplacer(":", "", "-", "", ".", "").Replace(value)
	if len(compact) == 12 && isHexString(compact) {
		return strings.Join([]string{
			compact[0:2],
			compact[2:4],
			compact[4:6],
			compact[6:8],
			compact[8:10],
			compact[10:12],
		}, ":")
	}
	return value
}

func isHexString(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func normalizeVLAN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return strconv.Itoa(i)
}
