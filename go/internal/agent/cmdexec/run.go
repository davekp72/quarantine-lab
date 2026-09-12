package cmdexec

import (
	"strings"
	"time"

	"github.com/quarantine-lab/quarantine/internal/agent/guestpaths"
	"github.com/quarantine-lab/quarantine/internal/agent/types"
)

func policy(cfg types.AgentConfig) guestpaths.FilePolicy {
	return guestpaths.FilePolicy{
		PayloadUser: cfg.PayloadUser,
		LabAdmin:    cfg.LabAdmin,
		SysmonDir:   cfg.SysmonDir,
	}
}

func resolveUser(req types.ExecRequest, cfg types.AgentConfig) (role, username string) {
	role = strings.ToLower(strings.TrimSpace(req.User))
	if role == "" {
		role = "system"
	}
	switch role {
	case "payload":
		return role, strings.TrimSpace(cfg.PayloadUser)
	case "guest":
		u := strings.TrimSpace(cfg.LabAdmin)
		if u == "" {
			u = "Administrator"
		}
		return role, u
	default:
		return "system", ""
	}
}

func timeoutOf(req types.ExecRequest) time.Duration {
	ms := req.TimeoutMs
	if ms <= 0 {
		ms = 120000
	}
	if ms > 30*60*1000 {
		ms = 30 * 60 * 1000
	}
	return time.Duration(ms) * time.Millisecond
}
