package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/app"
	"github.com/quarantine-lab/quarantine/internal/config"
	"github.com/quarantine-lab/quarantine/internal/gateway"
	guestpkg "github.com/quarantine-lab/quarantine/internal/guest"
	"github.com/spf13/cobra"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func defaultConfigPath() string {
	if v := os.Getenv("QUARANTINE_CONFIG"); v != "" {
		return v
	}
	candidates := []string{
		`config\quarantine-vm.json`,
		`..\config\quarantine-vm.json`,
		`..\..\config\quarantine-vm.json`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return `config\quarantine-vm.json`
}

func main() {
	cfgPath := defaultConfigPath()
	root := &cobra.Command{
		Use:   "quarantine",
		Short: "Quarantine lab VM and evidence manager",
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", cfgPath, "Path to quarantine-vm.json")
	root.PersistentFlags().BoolVar(&config.GuestAdditionsCLI, "guest-additions", false, "Use VirtualBox Guest Additions (guestcontrol, clipboard, VBOXSVR) instead of the agent")

	root.AddCommand(uiCmd(&cfgPath))
	root.AddCommand(statusCmd(&cfgPath))
	root.AddCommand(startCmd(&cfgPath))
	root.AddCommand(stopCmd(&cfgPath))
	root.AddCommand(snapshotCmd(&cfgPath))
	root.AddCommand(snapshotsCmd(&cfgPath))
	root.AddCommand(preserveCmd(&cfgPath))
	root.AddCommand(resetCmd(&cfgPath))
	root.AddCommand(baselineCmd(&cfgPath))
	root.AddCommand(deleteSnapshotCmd(&cfgPath))
	root.AddCommand(manifestCmd(&cfgPath))
	root.AddCommand(caseCmd(&cfgPath))
	root.AddCommand(networkCmd(&cfgPath))
	root.AddCommand(proxyCmd(&cfgPath))
	root.AddCommand(captureCmd(&cfgPath))
	root.AddCommand(gatewayCmd(&cfgPath))
	root.AddCommand(inboxCmd(&cfgPath))
	root.AddCommand(deployCmd(&cfgPath))
	root.AddCommand(setupCmd(&cfgPath))
	root.AddCommand(clipboardCmd(&cfgPath))
	root.AddCommand(guestCmd(&cfgPath))
	root.AddCommand(payloadCmd(&cfgPath))
	root.AddCommand(agentCmd(&cfgPath))
	root.AddCommand(stealthCmd(&cfgPath))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func uiCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "ui",
		Short: "Open Wails desktop report and lab UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return wails.Run(&options.App{
				Title:  "Quarantine Lab",
				Width:  1280,
				Height: 860,
				AssetServer: &assetserver.Options{
					Assets: assets,
				},
				Windows:   &windows.Options{WebviewIsTransparent: false},
				OnStartup: application.OnStartup,
				Bind:      []any{application},
			})
		},
	}
}

func statusCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show VM status",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			st, err := a.VMStatus(context.Background())
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		},
	}
}

func startCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.VM.Start(context.Background())
		},
	}
}

func stopCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.VM.Stop(context.Background())
		},
	}
}

func snapshotCmd(cfgPath *string) *cobra.Command {
	var name, desc string
	var offline, force bool
	c := &cobra.Command{
		Use:   "snapshot",
		Short: "Take a snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if !offline {
				return a.TakeSnapshotWails(name, desc, force)
			}
			return a.VM.SaveSnapshot(context.Background(), name, desc, offline, force)
		},
	}
	c.Flags().StringVar(&name, "name", "", "Snapshot name")
	c.Flags().StringVar(&desc, "description", "", "Description")
	c.Flags().BoolVar(&offline, "offline", false, "Disk-only snapshot")
	c.Flags().BoolVar(&force, "force", false, "Replace existing")
	return c
}

func snapshotsCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "snapshots",
		Short: "List snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			list, err := a.ListSnapshots(context.Background())
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(list)
		},
	}
}

func preserveCmd(cfgPath *string) *cobra.Command {
	var label string
	c := &cobra.Command{
		Use:   "preserve",
		Short: "Preserve evidence snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			// CLI defaults to stopping/attaching an active PCAP (UI prompts instead).
			name, err := a.PreserveEvidenceWails(label, true)
			if err != nil {
				return err
			}
			fmt.Println("Evidence snapshot:", name)
			return nil
		},
	}
	c.Flags().StringVar(&label, "label", "", "Evidence label")
	return c
}

func resetCmd(cfgPath *string) *cobra.Command {
	var snap string
	var clean bool
	c := &cobra.Command{
		Use:   "reset",
		Short: "Restore snapshot (clears guest Sysmon via agent; does not start PCAP)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.LaunchSnapshotWails(snap, clean)
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	}
	c.Flags().StringVar(&snap, "snapshot", "", "Snapshot name")
	c.Flags().BoolVar(&clean, "clean", false, "Restore clean snapshot")
	return c
}

func baselineCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "baseline",
		Short: "Flatten snapshots and save disk-only Clean",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.VM.Baseline(context.Background())
		},
	}
}

func deleteSnapshotCmd(cfgPath *string) *cobra.Command {
	var name string
	var force bool
	c := &cobra.Command{
		Use:   "delete-snapshot",
		Short: "Delete a snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			_, err = a.DeleteSnapshotWails(name, force)
			return err
		},
	}
	c.Flags().StringVar(&name, "name", "", "Snapshot name")
	c.Flags().BoolVar(&force, "force", false, "Delete protected baselines and child snapshots")
	return c
}

func manifestCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "manifest", Short: "Manifest and diff commands"}
	var from, to string
	var refresh bool
	cmd.AddCommand(&cobra.Command{
		Use:   "deploy",
		Short: "Deploy guest manifest scripts",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Evidence.DeployGuestScripts()
		},
	})
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			_, path, err := a.CompareSnapshots(context.Background(), from, to, refresh)
			if err != nil {
				return err
			}
			fmt.Println("Diff JSON:", path)
			return nil
		},
	}
	diffCmd.Flags().StringVar(&from, "from", "", "From snapshot")
	diffCmd.Flags().StringVar(&to, "to", "", "To snapshot")
	diffCmd.Flags().BoolVar(&refresh, "refresh", false, "Rebuild manifests from sidecars")
	cmd.AddCommand(diffCmd)
	viewCmd := &cobra.Command{
		Use:   "view",
		Short: "Build diff and open UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			_, path, err := a.CompareSnapshots(context.Background(), from, to, refresh)
			if err != nil {
				return err
			}
			fmt.Println("Diff JSON:", path)
			a.LastDiffPath = path
			return wails.Run(&options.App{
				Title:       "Quarantine Lab — Report",
				Width:       1280,
				Height:      860,
				AssetServer: &assetserver.Options{Assets: assets},
				Windows:     &windows.Options{},
				Bind:        []any{a},
			})
		},
	}
	viewCmd.Flags().StringVar(&from, "from", "", "From snapshot")
	viewCmd.Flags().StringVar(&to, "to", "", "To snapshot")
	viewCmd.Flags().BoolVar(&refresh, "refresh", true, "Rebuild manifests")
	cmd.AddCommand(viewCmd)
	return cmd
}

func caseCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "case", Short: "Saved compare cases"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List archived compares",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			list, err := a.ListCasesWails()
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Println("No saved cases")
				return nil
			}
			raw, err := json.MarshalIndent(list, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(raw))
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show [id]",
		Short: "Print archived compare JSON path",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("case id required")
			}
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			res, err := a.LoadCaseWails(args[0])
			if err != nil {
				return err
			}
			fmt.Println(res["id"], res["fromSnapshot"], "→", res["toSnapshot"])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a saved case (not VM snapshots)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("case id required")
			}
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.DeleteCaseWails(args[0])
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	})
	return cmd
}

func networkCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "network", Short: "Network mode"}
	for _, mode := range []string{"quarantine", "gateway", "offline", "nat", "intnet", "none", "hostonly"} {
		m := mode
		cmd.AddCommand(&cobra.Command{
			Use: m,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := app.New(*cfgPath)
				if err != nil {
					return err
				}
				if err := a.Network.SetMode(m); err != nil {
					return err
				}
				fmt.Printf("Network mode set to %s\n", a.Cfg.Network.Mode)
				return nil
			},
		})
	}
	return cmd
}

func proxyCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "proxy", Short: "Mitmproxy control"}
	cmd.AddCommand(&cobra.Command{
		Use: "start", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Proxy.StartIfHostMode()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if a.Cfg.IsGatewayMode() {
				fmt.Println("Network mode is gateway — host proxy stop is a no-op.")
				return nil
			}
			return a.Proxy.Stop()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			fmt.Println(a.Proxy.Status())
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "export-ca", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			_, err = a.Proxy.ExportCA(a.Gateway.ExportCA)
			return err
		},
	})
	return cmd
}

func captureCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "capture", Short: "PCAP capture"}
	cmd.AddCommand(&cobra.Command{
		Use: "start", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			path, err := a.Capture.Start()
			if err != nil {
				return err
			}
			fmt.Println("PCAP:", path)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Capture.Stop()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			fmt.Println(a.Capture.Status())
			return nil
		},
	})
	return cmd
}

func gatewayCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "gateway", Short: "Linux quarantine gateway VM"}
	cmd.AddCommand(&cobra.Command{
		Use: "create", Short: "Create gateway VM shell (NAT + intnet)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.Gateway.Create()
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "start", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Gateway.Start()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Gateway.Stop()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			fmt.Println(a.Gateway.Status())
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "provision", Short: "Copy scripts and run first-boot on gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.Gateway.Provision()
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "export-ca", Short: "Copy mitm CA from gateway to host",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			path, err := a.Gateway.ExportCA()
			if err != nil {
				return err
			}
			fmt.Println(path)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "sync-logs", Short: "Pull PCAPs and proxy logs from gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.Gateway.SyncLogs()
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	})
	cleanPcaps := &cobra.Command{
		Use:   "clean-pcaps",
		Short: "Delete old PCAPs on the gateway (keeps active capture)",
		Long: `Remove leftover PCAPs under /var/log/quarantine/pcap on the Linux gateway.

By default deletes every non-active .pcap/.pcapng. Use --older-than to keep recent
files (examples: 24h, 7d). The active capture path is never removed.

  quarantine gateway clean-pcaps
  quarantine gateway clean-pcaps --older-than 7d
  quarantine gateway clean-pcaps --include-proxy
  quarantine gateway clean-pcaps --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			older, _ := cmd.Flags().GetString("older-than")
			includeProxy, _ := cmd.Flags().GetBool("include-proxy")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			age, err := parseAgeDuration(older)
			if err != nil {
				return err
			}
			msg, err := a.Gateway.CleanPcaps(gateway.CleanPcapsOpts{
				OlderThan:    age,
				IncludeProxy: includeProxy,
				DryRun:       dryRun,
			})
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	}
	cleanPcaps.Flags().String("older-than", "", "Only delete files older than this age (e.g. 24h, 7d); empty = all non-active")
	cleanPcaps.Flags().Bool("include-proxy", false, "Also truncate gateway proxy/mitm log files")
	cleanPcaps.Flags().Bool("dry-run", false, "List matching files without deleting")
	cmd.AddCommand(cleanPcaps)

	modeCmd := &cobra.Command{
		Use:   "mode [permissive|fakenet]",
		Short: "Show or set gateway traffic mode (permissive MITM vs FakeNet sinkhole)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				mode, msg, err := a.Gateway.TrafficMode()
				if msg != "" {
					fmt.Println(msg)
				} else {
					fmt.Println("traffic-mode=" + mode)
				}
				return err
			}
			msg, err := a.Gateway.SetTrafficMode(args[0])
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	}
	cmd.AddCommand(modeCmd)
	return cmd
}

// parseAgeDuration accepts Go durations plus a trailing "d" for days (e.g. 7d).
func parseAgeDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid --older-than %q (want Nd, e.g. 7d)", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("--older-than must be >= 0")
	}
	return d, nil
}

func inboxCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "inbox", Short: "Deliver samples (agent copy, or VBOXSVR with --guest-additions)"}
	cmd.AddCommand(&cobra.Command{
		Use: "open", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if err := a.Inbox.Open(); err != nil {
				return err
			}
			fmt.Println(a.Inbox.Status())
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "close", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if err := a.Inbox.Close(); err != nil {
				return err
			}
			fmt.Println(a.Inbox.Status())
			return nil
		},
	})
	return cmd
}

func deployCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "sysmon",
		Short: "Deploy sysmon (alias: use manifest deploy for scripts)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Evidence.DeployGuestScripts()
		},
	}
}

func setupCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Check dependencies and generate per-build secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			fmt.Println("VBox:", a.VM.VBox.Binary)
			fmt.Println("VM:", a.Cfg.VMName)
			fmt.Println("Manifest log:", a.Cfg.ManifestLogDir())
			fmt.Println("Secrets dir:", a.Cfg.SecretsDir())
			return nil
		},
	}
	var generate bool
	secrets := &cobra.Command{
		Use:   "secrets",
		Short: "Generate unique passwords + gateway SSH keys; render unattend and cloud-init",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			root := config.ProjectRoot(*cfgPath)
			msg, err := cfg.EnsureSecrets(*cfgPath, root, generate)
			if msg != "" {
				fmt.Println(msg)
			}
			if err != nil {
				return err
			}
			if err := cfg.PreflightCredentials(); err != nil {
				return err
			}
			fmt.Println("Credential preflight: ok")
			fmt.Println("Setup ISO (boot this):", filepath.Join(cfg.DataDir(), "unattend", "Win11-setup.iso"))
			fmt.Println("Unattend sidecar ISO:", filepath.Join(cfg.DataDir(), "unattend", "unattend.iso"))
			fmt.Println("Unattend floppy:", filepath.Join(cfg.DataDir(), "unattend", "unattend.img"))
			fmt.Println("SSH:", fmt.Sprintf("ssh -i %s -p %d %s@127.0.0.1", cfg.Network.Gateway.SSHPrivateKey, cfg.Network.Gateway.WithDefaults(cfg.Network.IntnetName).SSHHostPort, cfg.Network.Gateway.Username))
			fmt.Println("FirstLogon runs elevated guest provision from the setup ISO / floppy; disable autologon is included when that script is staged.")
			return nil
		},
	}
	secrets.Flags().BoolVar(&generate, "generate", true, "Generate missing unique passwords")
	cmd.AddCommand(secrets)
	return cmd
}

func clipboardCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "clipboard", Short: "Set clipboard mode"}
	for _, mode := range []string{"hosttoguest", "guesttohost", "bidirectional", "disabled"} {
		m := mode
		cmd.AddCommand(&cobra.Command{
			Use: m,
			RunE: func(cmd *cobra.Command, args []string) error {
				a, err := app.New(*cfgPath)
				if err != nil {
					return err
				}
				return a.Network.SetClipboard(m)
			},
		})
	}
	return cmd
}

func stealthCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stealth",
		Short: "Soften VirtualBox guest fingerprints (DMI/MAC/CPU)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.VM.ApplyStealth()
			if msg != "" {
				fmt.Println(msg)
			}
			return err
		},
	}
}

func guestCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "guest", Short: "Guest control (agent by default; --guest-additions for VBox)"}
	var exe, hostPath string
	var runArgs []string
	run := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if exe == "" {
				exe = a.Cfg.Guest.DefaultExe
			}
			if exe == "" {
				exe = `C:\Windows\System32\cmd.exe`
			}
			out, err := a.Evidence.Guest.Run(guestpkg.UserGuest, exe, runArgs, 0)
			if out != "" {
				fmt.Println(out)
			}
			return err
		},
	}
	run.Flags().StringVar(&exe, "exe", "", "Guest executable")
	run.Flags().StringSliceVar(&runArgs, "args", nil, "Guest arguments")
	cmd.AddCommand(run)

	copyC := &cobra.Command{
		Use:   "copy [--host path]",
		Short: "Copy a host file into the guest (default: guest.copyTargetDir)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			path := hostPath
			if path == "" && len(args) > 0 {
				path = args[0]
			}
			if path == "" {
				return fmt.Errorf("usage: quarantine guest copy --host <file>  (or positional path)")
			}
			dest, err := a.CopyHostFileToGuest(path, a.Cfg.Guest.CopyTargetDir)
			if err != nil {
				return err
			}
			fmt.Printf("Copied %s → %s (%s)\n", path, dest, a.Evidence.Guest.Transport().Name())
			return nil
		},
	}
	copyC.Flags().StringVar(&hostPath, "host", "", "Host file to copy")
	cmd.AddCommand(copyC)

	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Verify agent health (or guestcontrol with --guest-additions)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if err := a.Network.EnsureAgentPortForward(); err != nil {
				fmt.Println("agent port-forward:", err)
			}
			if err := a.Evidence.Guest.Ready(); err != nil {
				return err
			}
			fmt.Println("ok (" + a.Evidence.Guest.Transport().Name() + ")")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "provision",
		Short: "Stage all elevated first-boot scripts (agent, ACLs, gateway, Sysmon) into the guest",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.ProvisionGuest()
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "gateway-setup",
		Short: "Upload gateway commission scripts + CA into the lab guest",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.Evidence.Guest.DeployGatewaySetup(config.ProjectRoot(*cfgPath))
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "disable-autologon",
		Short: "Clear Windows AutoAdminLogon before taking the Clean baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.VM.DisableAutoLogon()
		},
	})
	return cmd
}

func payloadCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "payload", Short: "Run/copy as the payload user (agent session or --guest-additions)"}
	var exe, hostPath, targetDir string
	var runArgs []string
	run := &cobra.Command{
		Use:   "run",
		Short: "Run a program as the logged-on payload user",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if exe == "" {
				exe = a.Cfg.Payload.DefaultExe
			}
			if exe == "" {
				exe = `C:\Windows\System32\cmd.exe`
			}
			if len(runArgs) == 0 && len(args) > 0 {
				runArgs = args
			}
			out, err := a.Evidence.Guest.Run(guestpkg.UserPayload, exe, runArgs, time.Duration(a.Cfg.Payload.TimeoutMs)*time.Millisecond)
			if out != "" {
				fmt.Println(out)
			}
			return err
		},
	}
	run.Flags().StringVar(&exe, "exe", "", "Guest executable")
	run.Flags().StringSliceVar(&runArgs, "args", nil, "Guest arguments")
	cmd.AddCommand(run)

	cmd.AddCommand(&cobra.Command{
		Use:   "ps [command]",
		Short: "Run PowerShell as the payload user",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			ps := strings.Join(args, " ")
			out, err := a.Evidence.Guest.Run(
				guestpkg.UserPayload,
				`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				[]string{"-NoProfile", "-NonInteractive", "-Command", ps},
				time.Duration(a.Cfg.Payload.TimeoutMs)*time.Millisecond,
			)
			if out != "" {
				fmt.Println(out)
			}
			return err
		},
	})

	copyC := &cobra.Command{
		Use:   "copy [host-file]",
		Short: "Copy a host file into the payload copyTargetDir",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			path := hostPath
			if path == "" && len(args) > 0 {
				path = args[0]
			}
			if path == "" {
				return fmt.Errorf("usage: quarantine payload copy <host-file>")
			}
			dir := targetDir
			if dir == "" {
				dir = a.Cfg.Payload.CopyTargetDir
			}
			if dir == "" {
				dir = a.Cfg.Guest.CopyTargetDir
			}
			return a.Evidence.Guest.CopyTo(path, dir, a.Evidence.Guest.PayloadCreds())
		},
	}
	copyC.Flags().StringVar(&hostPath, "host", "", "Host file to copy")
	copyC.Flags().StringVar(&targetDir, "target", "", "Guest directory")
	cmd.AddCommand(copyC)
	return cmd
}

func agentCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Quarantine VM agent (HTTP evidence collector)"}
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Stage quarantine-agent into the guest (run Install-QuarantineAgent.ps1 elevated in VM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.InstallAgentWails()
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "sync-token",
		Short: "Copy agent token from guest to host secrets file",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			msg, err := a.SyncAgentTokenWails()
			if err != nil {
				return err
			}
			fmt.Println(msg)
			return nil
		},
	})
	var token string
	setTok := &cobra.Command{
		Use:   "set-token",
		Short: "Save agent bearer token on the host",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if err := a.Evidence.SaveHostAgentToken(token); err != nil {
				return err
			}
			fmt.Println("Token saved to", a.Cfg.Agent.TokenFile)
			return nil
		},
	}
	setTok.Flags().StringVar(&token, "token", "", "Bearer token from guest install output")
	_ = setTok.MarkFlagRequired("token")
	cmd.AddCommand(setTok)
	cmd.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Query agent /health (NAT, or Linux gateway in gateway mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			_ = a.Network.EnsureAgentPortForward()
			_ = a.Evidence.EnsureHostAgentToken()
			h, err := a.AgentHealthWails()
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(h)
		},
	})
	var waitMin int
	wait := &cobra.Command{
		Use:   "wait",
		Short: "Poll agent /health until FirstLogon finishes (default 90 minutes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			if err := a.Network.EnsureAgentPortForward(); err != nil {
				fmt.Println("agent port-forward:", err)
			}
			if waitMin <= 0 {
				waitMin = 90
			}
			fmt.Printf("Waiting up to %d min for agent health on %s:%d...\n", waitMin, a.Cfg.Agent.Host, a.Cfg.Agent.Port)
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(waitMin)*time.Minute)
			defer cancel()
			if err := a.Evidence.WaitForAgent(ctx); err != nil {
				return err
			}
			fmt.Println("Agent is ready.")
			return nil
		},
	}
	wait.Flags().IntVar(&waitMin, "minutes", 90, "Timeout in minutes")
	cmd.AddCommand(wait)
	return cmd
}
