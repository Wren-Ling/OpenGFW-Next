package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/apernet/OpenGFW/ruleset"
)

func TestLoadIdentityInventoryFormats(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "entries",
			body: `
entries:
  - id: vm-entries
    name: entries-format
`,
		},
		{
			name: "array",
			body: `
- id: vm-array
  name: array-format
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatalf("write inventory: %v", err)
			}

			entries, err := loadIdentityInventory(path)
			if err != nil {
				t.Fatalf("load inventory: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("len(entries) = %d, want 1", len(entries))
			}
			if entries[0].ID == "" || entries[0].Name == "" {
				t.Fatalf("entry was not decoded: %+v", entries[0])
			}
		})
	}
}

func TestIdentityMACMatchNormalizesSrcAndDst(t *testing.T) {
	entry := compileIdentityEntry(identityEntry{
		ID:   "vm-100",
		MACs: []string{"52-54-00-00-00-01"},
	})

	tests := []struct {
		name      string
		meta      map[string]string
		wantMatch string
	}{
		{
			name:      "src uppercase colon",
			meta:      map[string]string{"l2.src": "52:54:00:00:00:01"},
			wantMatch: "l2.src",
		},
		{
			name:      "src dotted",
			meta:      map[string]string{"l2.src": "5254.0000.0001"},
			wantMatch: "l2.src",
		},
		{
			name:      "dst unseparated uppercase",
			meta:      map[string]string{"l2.dst": "525400000001"},
			wantMatch: "l2.dst",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, source, value := entry.Match(ruleset.StreamInfo{Meta: tt.meta})
			if !match {
				t.Fatal("Match returned false")
			}
			if source != tt.wantMatch {
				t.Fatalf("source = %q, want %q", source, tt.wantMatch)
			}
			if value != "52:54:00:00:00:01" {
				t.Fatalf("value = %q, want normalized MAC", value)
			}
		})
	}
}

func TestIdentityIPMatchSingleAndCIDR(t *testing.T) {
	entry := compileIdentityEntry(identityEntry{
		ID:  "vm-100",
		IPs: []string{"192.0.2.10", "2001:db8:100::/48"},
	})

	tests := []struct {
		name      string
		info      ruleset.StreamInfo
		wantMatch string
	}{
		{
			name: "single source ip",
			info: ruleset.StreamInfo{
				SrcIP: net.ParseIP("192.0.2.10"),
				DstIP: net.ParseIP("198.51.100.1"),
			},
			wantMatch: "ip.src",
		},
		{
			name: "cidr destination ip",
			info: ruleset.StreamInfo{
				SrcIP: net.ParseIP("198.51.100.1"),
				DstIP: net.ParseIP("2001:db8:100::1234"),
			},
			wantMatch: "ip.dst",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, source, _ := entry.Match(tt.info)
			if !match {
				t.Fatal("Match returned false")
			}
			if source != tt.wantMatch {
				t.Fatalf("source = %q, want %q", source, tt.wantMatch)
			}
		})
	}
}

func TestIdentityInterfaceAndVLANConstraints(t *testing.T) {
	entry := compileIdentityEntry(identityEntry{
		ID:         "vm-100",
		MACs:       []string{"52:54:00:00:00:01"},
		Interfaces: []string{"ogfw-mon0"},
		VLANs:      []string{"0100"},
	})

	info := ruleset.StreamInfo{
		Meta: map[string]string{
			"l2.src":            "52:54:00:00:00:01",
			"capture.interface": "ogfw-mon0",
			"vlan.id":           "100",
		},
	}
	if match, _, _ := entry.Match(info); !match {
		t.Fatal("Match returned false with matching constraints")
	}

	info.Meta["capture.interface"] = "other0"
	if match, _, _ := entry.Match(info); match {
		t.Fatal("Match returned true with non-matching interface")
	}

	info.Meta["capture.interface"] = "ogfw-mon0"
	info.Meta["vlan.id"] = "200"
	if match, _, _ := entry.Match(info); match {
		t.Fatal("Match returned true with non-matching VLAN")
	}
}

func TestParseLibvirtDomainXML(t *testing.T) {
	entry, ok, err := parseLibvirtDomainXML([]byte(`
<domain type='kvm'>
  <name>vm-alpha</name>
  <uuid>11111111-2222-3333-4444-555555555555</uuid>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:AA:BB:CC'/>
    </interface>
    <interface type='network'>
      <mac address='5254.0000.0002'/>
    </interface>
  </devices>
</domain>
`), "")
	if err != nil {
		t.Fatalf("parseLibvirtDomainXML() error = %v", err)
	}
	if !ok {
		t.Fatal("parseLibvirtDomainXML() ok = false")
	}
	if entry.Source != "libvirt" {
		t.Fatalf("Source = %q, want libvirt", entry.Source)
	}
	if entry.ID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("ID = %q", entry.ID)
	}
	if entry.Name != "vm-alpha" {
		t.Fatalf("Name = %q, want vm-alpha", entry.Name)
	}
	wantMACs := []string{"52:54:00:aa:bb:cc", "52:54:00:00:00:02"}
	if !reflect.DeepEqual(entry.MACs, wantMACs) {
		t.Fatalf("MACs = %#v, want %#v", entry.MACs, wantMACs)
	}
}

func TestLibvirtInventoryProviderUsesVirshAndURI(t *testing.T) {
	var calls [][]string
	provider := &libvirtInventoryProvider{
		uri: "qemu:///system",
		runCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name != "virsh" {
				t.Fatalf("command name = %q, want virsh", name)
			}
			calls = append(calls, append([]string{name}, args...))
			switch {
			case reflect.DeepEqual(args, []string{"--connect", "qemu:///system", "list", "--all", "--name"}):
				return []byte("vm-alpha\n\nvm-beta\n"), nil
			case reflect.DeepEqual(args, []string{"--connect", "qemu:///system", "dumpxml", "vm-alpha"}):
				return []byte(libvirtDomainXMLFixture("vm-alpha", "uuid-alpha", "52:54:00:00:00:01")), nil
			case reflect.DeepEqual(args, []string{"--connect", "qemu:///system", "dumpxml", "vm-beta"}):
				return []byte(libvirtDomainXMLFixture("vm-beta", "uuid-beta", "52-54-00-00-00-02")), nil
			default:
				t.Fatalf("unexpected args: %#v", args)
			}
			return nil, nil
		},
	}

	entries, err := provider.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].ID != "uuid-alpha" || entries[0].Name != "vm-alpha" || entries[0].MACs[0] != "52:54:00:00:00:01" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	if entries[1].ID != "uuid-beta" || entries[1].Name != "vm-beta" || entries[1].MACs[0] != "52:54:00:00:00:02" {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %#v, want list plus two dumpxml calls", calls)
	}
}

func TestIdentityLibvirtMetadataAndStaticPriority(t *testing.T) {
	static := []compiledIdentityEntry{
		compileIdentityEntry(identityEntry{
			ID:     "static-id",
			Name:   "static-name",
			MACs:   []string{"52:54:00:00:00:01"},
			Source: "inventory",
		}),
	}
	dynamic := []identityEntry{
		{
			ID:     "libvirt-id",
			Name:   "libvirt-name",
			MACs:   []string{"52:54:00:00:00:01"},
			Source: "libvirt",
		},
	}
	enricher := &identityEnricher{}
	enricher.entries.Store(mergeIdentityEntries(static, dynamic))

	meta := enricher.Enrich(ruleset.StreamInfo{
		Meta: map[string]string{"l2.src": "52:54:00:00:00:01"},
	})
	if meta["identity.source"] != "inventory" {
		t.Fatalf("identity.source = %q, want static inventory priority", meta["identity.source"])
	}
	if meta["vm.id"] != "static-id" || meta["vm.name"] != "static-name" {
		t.Fatalf("metadata = %#v, want static VM identity", meta)
	}

	enricher.entries.Store(mergeIdentityEntries(nil, []identityEntry{
		{
			ID:     "libvirt-id",
			Name:   "libvirt-name",
			MACs:   []string{"52:54:00:00:00:01"},
			Source: "libvirt",
		},
	}))
	meta = enricher.Enrich(ruleset.StreamInfo{
		Meta: map[string]string{"l2.dst": "52-54-00-00-00-01"},
	})
	if meta["identity.source"] != "libvirt" {
		t.Fatalf("identity.source = %q, want libvirt", meta["identity.source"])
	}
	if meta["vm.id"] != "libvirt-id" || meta["vm.name"] != "libvirt-name" || meta["vm.mac"] != "52:54:00:00:00:01" {
		t.Fatalf("metadata = %#v, want libvirt VM identity", meta)
	}
}

func libvirtDomainXMLFixture(name, uuid, mac string) string {
	return `
<domain type='kvm'>
  <name>` + name + `</name>
  <uuid>` + uuid + `</uuid>
  <devices>
    <interface type='bridge'>
      <mac address='` + mac + `'/>
    </interface>
  </devices>
</domain>`
}
