package cmd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/ruleset"
)

func TestWebhookAlertSinkPostsEventJSON(t *testing.T) {
	received := make(chan map[string]interface{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := r.Header.Get("X-Test"); got != "yes" {
			t.Errorf("X-Test = %q, want yes", got)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode JSON: %v", err)
		}
		received <- body
		w.WriteHeader(http.StatusNoContent)
	})
	listener := newPipeListener()
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	server.Start()
	defer server.Close()

	s := &webhookAlertSink{
		url:     "http://opengfw-alert.test/event",
		headers: map[string]string{"X-Test": "yes"},
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return listener.DialContext(ctx)
				},
			},
		},
	}
	event := newAlertEvent(ruleset.StreamInfo{
		ID:       42,
		Protocol: ruleset.ProtocolUDP,
		SrcIP:    net.ParseIP("192.0.2.10"),
		DstIP:    net.ParseIP("198.51.100.20"),
		SrcPort:  51820,
		DstPort:  443,
		Meta: map[string]string{
			"vm.id":  "vm-100",
			"vm.mac": "52:54:00:00:00:01",
		},
		Props: analyzer.CombinedPropMap{
			"wireguard": analyzer.PropMap{"message_type": uint8(1)},
		},
	}, "vpn-wireguard", ruleset.MatchMetadata{Severity: "high"})

	if err := s.post(event); err != nil {
		t.Fatalf("post() error = %v", err)
	}

	select {
	case body := <-received:
		if body["rule"] != "vpn-wireguard" {
			t.Fatalf("rule = %v, want vpn-wireguard", body["rule"])
		}
		if body["severity"] != "high" {
			t.Fatalf("severity = %v, want high", body["severity"])
		}
		meta, ok := body["meta"].(map[string]interface{})
		if !ok {
			t.Fatalf("meta has type %T, want object", body["meta"])
		}
		if meta["vm.id"] != "vm-100" || meta["vm.mac"] != "52:54:00:00:00:01" {
			t.Fatalf("meta = %#v, want VM identity fields", meta)
		}
		props, ok := body["props"].(map[string]interface{})
		if !ok {
			t.Fatalf("props has type %T, want object", body["props"])
		}
		if _, ok := props["wireguard"].(map[string]interface{}); !ok {
			t.Fatalf("props = %#v, want wireguard object", props)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for webhook request")
	}
}

type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.done)
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr("pipe")
}

func (l *pipeListener) DialContext(ctx context.Context) (net.Conn, error) {
	serverConn, clientConn := net.Pipe()
	select {
	case l.conns <- serverConn:
		return clientConn, nil
	case <-l.done:
		serverConn.Close()
		clientConn.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		serverConn.Close()
		clientConn.Close()
		return nil, ctx.Err()
	}
}

type pipeAddr string

func (a pipeAddr) Network() string {
	return string(a)
}

func (a pipeAddr) String() string {
	return string(a)
}
