package cmd

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOVSQuarantineListUsesOVSOfctl(t *testing.T) {
	var calls [][]string
	cmd := newTestOVSQuarantineCommand(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		calls = append(calls, append([]string{name}, args...))
		return []byte(" cookie=0x4f474657,dl_src=52:54:00:00:00:01 actions=drop\n"), nil
	})
	out, err := executeCommand(cmd, "ovs-quarantine", "list", "--bridge", "br0", "--cookie", "0x4f474657", "-O", "OpenFlow13")
	if err != nil {
		t.Fatalf("list error = %v", err)
	}

	wantCalls := [][]string{{
		"ovs-ofctl",
		"-O",
		"OpenFlow13",
		"dump-flows",
		"br0",
		"cookie=0x4f474657/-1",
	}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if !strings.Contains(out, "OpenGFW quarantine flows on br0") ||
		!strings.Contains(out, "dl_src=52:54:00:00:00:01") {
		t.Fatalf("output = %q, want readable flow list", out)
	}
}

func TestOVSQuarantineReleaseDeletesSrcAndDst(t *testing.T) {
	var calls [][]string
	cmd := newTestOVSQuarantineCommand(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	})
	out, err := executeCommand(cmd, "ovs-quarantine", "release", "--bridge", "br0", "--cookie", "0x4f474657", "--mac", "52-54-00-00-00-01")
	if err != nil {
		t.Fatalf("release error = %v", err)
	}

	wantCalls := [][]string{
		{
			"ovs-ofctl",
			"del-flows",
			"br0",
			"cookie=0x4f474657/-1,dl_src=52:54:00:00:00:01",
		},
		{
			"ovs-ofctl",
			"del-flows",
			"br0",
			"cookie=0x4f474657/-1,dl_dst=52:54:00:00:00:01",
		},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if !strings.Contains(out, "Released OpenGFW quarantine flows for 52:54:00:00:00:01") {
		t.Fatalf("output = %q, want release confirmation", out)
	}
}

func TestOVSQuarantineClearDeletesCookieFlows(t *testing.T) {
	var calls [][]string
	cmd := newTestOVSQuarantineCommand(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		calls = append(calls, append([]string{name}, args...))
		return []byte("ok"), nil
	})
	out, err := executeCommand(cmd, "ovs-quarantine", "clear", "--bridge", "br0", "--cookie", "0x4f474657")
	if err != nil {
		t.Fatalf("clear error = %v", err)
	}

	wantCalls := [][]string{{
		"ovs-ofctl",
		"del-flows",
		"br0",
		"cookie=0x4f474657/-1",
	}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if !strings.Contains(out, "Cleared OpenGFW quarantine flows on br0") {
		t.Fatalf("output = %q, want clear confirmation", out)
	}
}

func TestOVSQuarantineCommandErrorIncludesOVSOfctlOutput(t *testing.T) {
	cmd := newTestOVSQuarantineCommand(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 1")
	})
	_, err := executeCommand(cmd, "ovs-quarantine", "clear", "--bridge", "br0")
	if err == nil {
		t.Fatal("clear error = nil")
	}
	for _, want := range []string{"ovs-ofctl del-flows br0 cookie=0x4f474657/-1", "permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

func newTestOVSQuarantineCommand(runCommand commandRunner) *cobra.Command {
	root := &cobra.Command{Use: "OpenGFW"}
	root.AddCommand(newOVSQuarantineCommand(runCommand))
	return root
}

func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}
