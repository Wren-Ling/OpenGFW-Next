package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const defaultOVSQuarantineCookie = "0x4f474657"

type ovsQuarantineOptions struct {
	bridge         string
	cookie         string
	mac            string
	ofctl          string
	openFlow       string
	commandTimeout time.Duration
	runCommand     commandRunner
}

func newOVSQuarantineCommand(runCommand commandRunner) *cobra.Command {
	opts := &ovsQuarantineOptions{
		cookie:         defaultOVSQuarantineCookie,
		ofctl:          "ovs-ofctl",
		commandTimeout: defaultOVSResponseCommandTimeout,
		runCommand:     runCommand,
	}
	cmd := &cobra.Command{
		Use:   "ovs-quarantine",
		Short: "Manage OpenGFW OVS quarantine flows",
	}
	cmd.PersistentFlags().StringVar(&opts.bridge, "bridge", "", "OVS bridge name")
	cmd.PersistentFlags().StringVar(&opts.cookie, "cookie", defaultOVSQuarantineCookie, "OpenGFW quarantine flow cookie")
	cmd.PersistentFlags().StringVar(&opts.ofctl, "ofctl", "ovs-ofctl", "ovs-ofctl binary path")
	cmd.PersistentFlags().StringVarP(&opts.openFlow, "openflow", "O", "", "OpenFlow version for ovs-ofctl, e.g. OpenFlow13")
	cmd.PersistentFlags().DurationVar(&opts.commandTimeout, "command-timeout", defaultOVSResponseCommandTimeout, "ovs-ofctl command timeout")
	_ = cmd.MarkPersistentFlagRequired("bridge")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List OpenGFW quarantine flows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.list(cmd.OutOrStdout())
		},
	}

	releaseCmd := &cobra.Command{
		Use:   "release",
		Short: "Release one quarantined MAC",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.release(cmd.OutOrStdout())
		},
	}
	releaseCmd.Flags().StringVar(&opts.mac, "mac", "", "MAC address to release")
	_ = releaseCmd.MarkFlagRequired("mac")

	clearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear all OpenGFW quarantine flows for the cookie",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.clear(cmd.OutOrStdout())
		},
	}

	cmd.AddCommand(listCmd, releaseCmd, clearCmd)
	return cmd
}

func (o *ovsQuarantineOptions) list(w io.Writer) error {
	output, err := o.ovsCommand("dump-flows", o.bridge, o.cookieMatch())
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		fmt.Fprintf(w, "No OpenGFW quarantine flows on %s for cookie %s.\n", o.bridge, o.cookie)
		return nil
	}
	fmt.Fprintf(w, "OpenGFW quarantine flows on %s for cookie %s:\n%s\n", o.bridge, o.cookie, text)
	return nil
}

func (o *ovsQuarantineOptions) release(w io.Writer) error {
	mac := normalizeMAC(o.mac)
	if _, err := net.ParseMAC(mac); err != nil {
		return fmt.Errorf("invalid mac %q: %w", o.mac, err)
	}
	for _, field := range []string{"dl_src", "dl_dst"} {
		if _, err := o.ovsCommand("del-flows", o.bridge, o.cookieMatch()+","+field+"="+mac); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "Released OpenGFW quarantine flows for %s on %s.\n", mac, o.bridge)
	return nil
}

func (o *ovsQuarantineOptions) clear(w io.Writer) error {
	if _, err := o.ovsCommand("del-flows", o.bridge, o.cookieMatch()); err != nil {
		return err
	}
	fmt.Fprintf(w, "Cleared OpenGFW quarantine flows on %s for cookie %s.\n", o.bridge, o.cookie)
	return nil
}

func (o *ovsQuarantineOptions) cookieMatch() string {
	return "cookie=" + o.cookie + "/-1"
}

func (o *ovsQuarantineOptions) ovsCommand(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.commandTimeout)
	defer cancel()

	fullArgs := []string{}
	if o.openFlow != "" {
		fullArgs = append(fullArgs, "-O", o.openFlow)
	}
	fullArgs = append(fullArgs, args...)

	runCommand := o.runCommand
	if runCommand == nil {
		runCommand = execCommandRunner
	}
	output, err := runCommand(ctx, o.ofctl, fullArgs...)
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", o.ofctl, strings.Join(fullArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
