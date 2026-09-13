package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/quarantine-lab/quarantine/internal/agent/agentsvc"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func main() {
	// SCM starts the service without going through subcommand routing.
	if isSvc, err := agentsvc.IsWindowsService(); err == nil && isSvc {
		runAgent(true)
		return
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		if err := agentsvc.Uninstall(); err != nil {
			fatal(err)
		}
	case "run":
		runAgent(true)
	case "debug":
		runAgent(false)
	default:
		usage()
		os.Exit(2)
	}
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	token := fs.String("token", "", "Bearer token (generated if empty)")
	port := fs.Int("port", 9443, "Listen port")
	payloadUser := fs.String("payload-user", "analyst", "Payload/test user for HKCU capture")
	labAdmin := fs.String("lab-admin", "", "Lab admin account name for /v1/exec user=guest")
	sysmonLog := fs.String("sysmon-log", `Microsoft-Windows-Sysmon/Operational`, "Sysmon event log name")
	_ = fs.Parse(args)

	tok := *token
	if tok == "" {
		tok = randomToken()
	}
	cfg := types.AgentConfig{
		Port:        *port,
		TokenFile:   agentsvc.DefaultTokenPath(),
		PayloadUser: *payloadUser,
		LabAdmin:    *labAdmin,
		SysmonLog:   *sysmonLog,
	}
	if err := agentsvc.Install("", tok, cfg); err != nil {
		fatal(err)
	}
	fmt.Println("Installed", agentsvc.ServiceName)
	fmt.Println("Token:", tok)
}

func runAgent(asService bool) {
	cfg, err := agentsvc.LoadConfig()
	if err != nil {
		cfg = types.AgentConfig{Port: 9443, TokenFile: agentsvc.DefaultTokenPath(), PayloadUser: "analyst"}
	}
	token, err := agentsvc.LoadToken(cfg.TokenFile)
	if err != nil {
		fatal(fmt.Errorf("load token: %w", err))
	}
	if asService {
		if err := agentsvc.RunService(token, cfg); err != nil {
			fatal(err)
		}
		return
	}
	if err := agentsvc.RunConsole(token, cfg); err != nil {
		fatal(err)
	}
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Quarantine Lab VM Agent

Usage:
  quarantine-agent install [--token=...] [--port=9443] [--payload-user=analyst]
  quarantine-agent uninstall
  quarantine-agent run          (service entry or console)
  quarantine-agent debug        (console)

`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
