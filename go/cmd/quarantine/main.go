package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/quarantine-lab/quarantine/internal/app"
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
	root.AddCommand(networkCmd(&cfgPath))
	root.AddCommand(proxyCmd(&cfgPath))
	root.AddCommand(captureCmd(&cfgPath))
	root.AddCommand(gatewayCmd(&cfgPath))
	root.AddCommand(inboxCmd(&cfgPath))
	root.AddCommand(deployCmd(&cfgPath))
	root.AddCommand(setupCmd(&cfgPath))
	root.AddCommand(clipboardCmd(&cfgPath))
	root.AddCommand(guestCmd(&cfgPath))
	root.AddCommand(agentCmd(&cfgPath))

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
				Windows: &windows.Options{WebviewIsTransparent: false},
				OnStartup: application.OnStartup,
				Bind: []any{application},
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
			name, err := a.VM.Preserve(context.Background(), label)
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
		Short: "Restore snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.VM.Launch(context.Background(), snap, clean)
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
				Title:  "Quarantine Lab — Report",
				Width:  1280,
				Height: 860,
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

func networkCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "network", Short: "Network mode"}
	for _, mode := range []string{"quarantine", "gateway", "offline", "nat", "intnet", "none", "hostonly"} {
		m := mode
		cmd.AddCommand(&cobra.Command{
			Use:  m,
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
			a, err := app.New(*cfgPath); if err != nil { return err }
			return a.Proxy.StartIfHostMode()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			if a.Cfg.IsGatewayMode() {
				fmt.Println("Network mode is gateway — host proxy stop is a no-op.")
				return nil
			}
			return a.Proxy.Stop()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			fmt.Println(a.Proxy.Status()); return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "export-ca", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
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
			a, err := app.New(*cfgPath); if err != nil { return err }
			path, err := a.Capture.Start(); if err != nil { return err }
			fmt.Println("PCAP:", path); return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			return a.Capture.Stop()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			fmt.Println(a.Capture.Status()); return nil
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
	return cmd
}

func inboxCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "inbox", Short: "Inbox shared folder"}
	cmd.AddCommand(&cobra.Command{
		Use: "open", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			return a.Inbox.Open()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "close", RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath); if err != nil { return err }
			return a.Inbox.Close()
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
	return &cobra.Command{
		Use:   "setup",
		Short: "Check dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			fmt.Println("VBox:", a.VM.VBox.Binary)
			fmt.Println("VM:", a.Cfg.VMName)
			fmt.Println("Manifest log:", a.Cfg.ManifestLogDir())
			return nil
		},
	}
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

func guestCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "guest", Short: "Guest control (admin lab account)"}
	var exe, hostPath string
	var runArgs []string
	run := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			creds := a.Evidence.Guest.GuestCreds()
			if exe == "" {
				exe = a.Cfg.Guest.DefaultExe
			}
			out, err := a.VM.VBox.GuestControlRun(a.Cfg.VMName, creds.Username, creds.Password, exe, runArgs, 0)
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
		Use: "copy",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := app.New(*cfgPath)
			if err != nil {
				return err
			}
			return a.Evidence.Guest.CopyTo(hostPath, a.Cfg.Guest.CopyTargetDir, a.Evidence.Guest.GuestCreds())
		},
	}
	copyC.Flags().StringVar(&hostPath, "host", "", "Host file to copy")
	cmd.AddCommand(copyC)
	return cmd
}

func agentCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Quarantine VM agent (HTTP evidence collector)"}
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Deploy quarantine-agent files and guest install script (run script elevated in VM)",
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
		Short: "Query agent /health via NAT port forward",
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
	return cmd
}
