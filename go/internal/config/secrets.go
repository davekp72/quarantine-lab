package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/quarantine-lab/quarantine/internal/unattend"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func stageUnattendMedia(projectRoot, mediaDir, renderedAutounattend, windowsISO, payloadUser, labAdmin, guestPassword, payloadPassword string, extras unattend.StageExtras) (string, []string, error) {
	return unattend.StageFiles(projectRoot, mediaDir, renderedAutounattend, windowsISO, payloadUser, labAdmin, guestPassword, payloadPassword, extras)
}

func (c *Config) resolveWindowsISOFile(projectRoot string) string {
	p := strings.TrimSpace(c.WindowsISOPath)
	if p == "" {
		p = "isos"
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(projectRoot, p)
	}
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if !st.IsDir() {
		return p
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return ""
	}
	var isos []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".iso") {
			isos = append(isos, filepath.Join(p, name))
		}
	}
	if len(isos) == 0 {
		return ""
	}
	// Prefer names that look like Windows install media.
	for _, iso := range isos {
		base := strings.ToLower(filepath.Base(iso))
		if strings.Contains(base, "win11") || strings.Contains(base, "windows") {
			return iso
		}
	}
	return isos[0]
}

var knownDefaultPasswords = []string{
	"quarantine",
	"changeme-quarantine!",
	"changeme",
	"password",
	"admin",
	"123456",
	"linux",
	"ubuntu",
}

// SecretsDir is {vmDataDir}/secrets.
func (c *Config) SecretsDir() string {
	if c == nil {
		return ""
	}
	return filepath.Join(c.DataDir(), "secrets")
}

func (c *Config) defaultGuestPasswordFile() string {
	return filepath.Join(c.SecretsDir(), "guest-password.txt")
}
func (c *Config) defaultPayloadPasswordFile() string {
	return filepath.Join(c.SecretsDir(), "payload-password.txt")
}
func (c *Config) defaultGatewayPasswordFile() string {
	return filepath.Join(c.SecretsDir(), "gateway-password.txt")
}
func (c *Config) defaultGatewaySSHPrivate() string {
	return filepath.Join(c.SecretsDir(), "gateway-id_ed25519")
}
func (c *Config) defaultGatewaySSHPublic() string {
	return filepath.Join(c.SecretsDir(), "gateway-id_ed25519.pub")
}

// IsKnownDefaultPassword reports shipped/example credentials that must not be used.
func IsKnownDefaultPassword(s string) bool {
	p := strings.ToLower(strings.TrimSpace(s))
	if p == "" {
		return false
	}
	for _, d := range knownDefaultPasswords {
		if p == d {
			return true
		}
	}
	return false
}

// GeneratePassword returns a unique Windows-complexity password (never a known default).
func GeneratePassword() (string, error) {
	const letters = "abcdefghijkmnopqrstuvwxyz"
	const uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const digits = "23456789"
	const symbols = "!@#$%^&*-_=+"
	classes := []string{letters, uppers, digits, symbols}
	var b strings.Builder
	b.Grow(20)
	for _, cls := range classes {
		c, err := randChar(cls)
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
	}
	all := letters + uppers + digits + symbols
	for b.Len() < 20 {
		c, err := randChar(all)
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
	}
	raw := []byte(b.String())
	if err := shuffleBytes(raw); err != nil {
		return "", err
	}
	out := string(raw)
	if IsKnownDefaultPassword(out) {
		return GeneratePassword()
	}
	return out, nil
}

func randChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, bigInt(len(set)))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func shuffleBytes(raw []byte) error {
	for i := len(raw) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, bigInt(i+1))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		raw[i], raw[j] = raw[j], raw[i]
	}
	return nil
}

// EnsureSecrets creates missing unique passwords and SSH keys, and writes
// unattend + cloud-init. Passwords live in the gitignored quarantine-vm.json
// (passwordFile is only an optional fallback). Existing values are kept.
func (c *Config) EnsureSecrets(cfgPath, projectRoot string, generate bool) (string, error) {
	if c == nil {
		return "", fmt.Errorf("nil config")
	}
	if err := os.MkdirAll(c.SecretsDir(), 0o700); err != nil {
		return "", err
	}
	var notes []string
	for _, item := range []struct {
		name string
		acc  *AccountConfig
	}{
		{"guest", &c.Guest},
		{"payload", &c.Payload},
	} {
		n, err := ensureInlinePassword(&item.acc.Password, item.acc.PasswordFile, item.name, generate)
		if err != nil {
			return "", fmt.Errorf("%s password: %w", item.name, err)
		}
		if n != "" {
			notes = append(notes, n)
		}
	}
	gw := &c.Network.Gateway
	n, err := ensureInlinePassword(&gw.Password, gw.PasswordFile, "gateway", generate)
	if err != nil {
		return "", fmt.Errorf("gateway password: %w", err)
	}
	if n != "" {
		notes = append(notes, n)
	}
	if strings.TrimSpace(gw.SSHPrivateKey) == "" {
		gw.SSHPrivateKey = c.defaultGatewaySSHPrivate()
	}
	if strings.TrimSpace(gw.SSHPublicKey) == "" {
		gw.SSHPublicKey = c.defaultGatewaySSHPublic()
	}
	if _, err := os.Stat(gw.SSHPrivateKey); err != nil {
		if err := writeEd25519Keypair(gw.SSHPrivateKey, gw.SSHPublicKey); err != nil {
			return "", err
		}
		notes = append(notes, "wrote "+gw.SSHPrivateKey)
	}
	unattendOut := filepath.Join(c.DataDir(), "unattend", "autounattend.xml")
	// Always prefer the repo template so FirstLogonCommands stay current after upgrades.
	tmpl := filepath.Join(projectRoot, "templates", "autounattend.xml")
	if _, err := os.Stat(tmpl); err != nil {
		tmpl = strings.TrimSpace(c.AutounattendPath)
	}
	if tmpl != "" {
		if _, err := os.Stat(tmpl); err == nil {
			if err := c.RenderUnattend(tmpl, unattendOut); err != nil {
				return "", err
			}
			c.AutounattendPath = unattendOut
			notes = append(notes, "rendered "+unattendOut)

			guestUser := strings.TrimSpace(c.Guest.Username)
			if guestUser == "" {
				guestUser = DefaultGuestUsername
			}
			payloadUser := strings.TrimSpace(c.Payload.Username)
			if payloadUser == "" {
				payloadUser = DefaultPayloadUsername
			}
			mediaDir := filepath.Join(c.DataDir(), "unattend", "media")
			winISO := c.resolveWindowsISOFile(projectRoot)
			extras, extraErr := c.unattendStageExtras(projectRoot, &notes)
			if extraErr != nil {
				return strings.Join(notes, "\n"), extraErr
			}
			floppyPath, stageNotes, stageErr := stageUnattendMedia(projectRoot, mediaDir, unattendOut, winISO, payloadUser, guestUser, c.Guest.Password, c.Payload.Password, extras)
			for _, n := range stageNotes {
				notes = append(notes, n)
			}
			if stageErr != nil {
				return strings.Join(notes, "\n"), fmt.Errorf("unattend media: %w", stageErr)
			}
			if floppyPath != "" {
				notes = append(notes, "floppy ready: "+floppyPath)
			}
			setupISO := filepath.Join(c.DataDir(), "unattend", "Win11-setup.iso")
			if _, err := os.Stat(setupISO); err == nil {
				notes = append(notes, "install DVD: "+setupISO)
			}
		}
	}
	cloudSrc := filepath.Join(projectRoot, "gateway", "cloud-init", "user-data")
	cloudOut := filepath.Join(c.DataDir(), "gateway", "user-data")
	if _, err := os.Stat(cloudSrc); err == nil {
		if err := c.RenderCloudInit(cloudSrc, cloudOut); err != nil {
			return "", err
		}
		notes = append(notes, "rendered "+cloudOut)
	}
	if err := c.persistConfigSecrets(cfgPath); err != nil {
		return strings.Join(notes, "\n"), err
	}
	notes = append(notes, "updated config (passwords kept in gitignored quarantine-vm.json)")
	return strings.Join(notes, "\n"), nil
}

func (c *Config) unattendStageExtras(projectRoot string, notes *[]string) (unattend.StageExtras, error) {
	extras := unattend.StageExtras{
		AgentPort:    c.Agent.Port,
		SysmonExe:    firstExistingFile(resolveProjectFile(projectRoot, c.Sysmon.HostSysmonExe), filepath.Join(projectRoot, "tools", "Sysmon64.exe")),
		SysmonConfig: firstExistingFile(resolveProjectFile(projectRoot, c.Sysmon.HostConfigPath), filepath.Join(projectRoot, "config", "sysmon", "quarantine-lab.xml")),
	}
	if !c.Agent.Enabled {
		return extras, nil
	}
	if strings.TrimSpace(c.Agent.TokenFile) == "" {
		c.Agent.TokenFile = filepath.Join(c.SecretsDir(), "agent-token.txt")
	}
	if _, err := os.Stat(c.Agent.TokenFile); err != nil {
		if err := c.SaveAgentToken(generateAgentToken()); err != nil {
			return extras, fmt.Errorf("agent token: %w", err)
		}
		*notes = append(*notes, "wrote "+c.Agent.TokenFile)
	}
	if tok, err := c.AgentToken(); err == nil {
		extras.AgentToken = tok
	} else {
		return extras, err
	}
	bin := c.AgentHostBinary(projectRoot)
	if _, err := os.Stat(bin); err != nil {
		*notes = append(*notes, "skip quarantine-agent.exe (build the agent, then re-run setup secrets)")
		return extras, nil
	}
	extras.AgentExe = bin
	return extras, nil
}

func resolveProjectFile(projectRoot, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(projectRoot, filepath.FromSlash(p))
}

func firstExistingFile(paths ...string) string {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func generateAgentToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ensureInlinePassword prefers config JSON password; passwordFile is optional fallback only.
func ensureInlinePassword(inline *string, filePath, label string, generate bool) (string, error) {
	pw := strings.TrimSpace(*inline)
	if pw != "" && !IsKnownDefaultPassword(pw) {
		return "", nil
	}
	if path := strings.TrimSpace(filePath); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			filePW := strings.TrimSpace(string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
			if filePW != "" && !IsKnownDefaultPassword(filePW) {
				*inline = filePW
				return "loaded " + label + " password from " + path + " into config", nil
			}
		}
	}
	if pw != "" && IsKnownDefaultPassword(pw) && !generate {
		return "", nil
	}
	if !generate {
		return "", nil
	}
	next, err := GeneratePassword()
	if err != nil {
		return "", err
	}
	*inline = next
	return "generated " + label + " password in config", nil
}

func writeSecretFile(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}))), nil
}

func writeEd25519Keypair(privPath, pubPath string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("marshal ssh key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return err
	}
	return os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644)
}

func (c *Config) hydrateSecrets() (dirty bool, err error) {
	if c.Network.Gateway.SSHPrivateKey == "" {
		c.Network.Gateway.SSHPrivateKey = c.defaultGatewaySSHPrivate()
		dirty = true
	}
	if c.Network.Gateway.SSHPublicKey == "" {
		c.Network.Gateway.SSHPublicKey = c.defaultGatewaySSHPublic()
		dirty = true
	}
	// Optional passwordFile fallback when JSON password is empty (legacy installs).
	for _, pair := range []struct {
		pw   *string
		file string
	}{
		{&c.Guest.Password, c.Guest.PasswordFile},
		{&c.Payload.Password, c.Payload.PasswordFile},
		{&c.Network.Gateway.Password, c.Network.Gateway.PasswordFile},
	} {
		if strings.TrimSpace(*pair.pw) != "" {
			continue
		}
		if strings.TrimSpace(pair.file) == "" {
			continue
		}
		if filePW, rerr := readSecretFile(pair.file); rerr == nil && filePW != "" {
			*pair.pw = filePW
			dirty = true
		}
	}
	return dirty, nil
}

// persistConfigSecrets writes passwords + usernames + SSH key paths into the gitignored config JSON.
func (c *Config) persistConfigSecrets(cfgPath string) error {
	if strings.TrimSpace(cfgPath) == "" {
		return nil
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	writeAccount := func(key string, acc AccountConfig) {
		obj, _ := doc[key].(map[string]any)
		if obj == nil {
			obj = map[string]any{}
			doc[key] = obj
		}
		if strings.TrimSpace(acc.Username) != "" {
			obj["username"] = acc.Username
		}
		obj["password"] = acc.Password
		if strings.TrimSpace(acc.PasswordFile) != "" {
			obj["passwordFile"] = acc.PasswordFile
		}
	}
	writeAccount("guest", c.Guest)
	writeAccount("payload", c.Payload)
	netObj, _ := doc["network"].(map[string]any)
	if netObj == nil {
		netObj = map[string]any{}
		doc["network"] = netObj
	}
	gwObj, _ := netObj["gateway"].(map[string]any)
	if gwObj == nil {
		gwObj = map[string]any{}
		netObj["gateway"] = gwObj
	}
	if strings.TrimSpace(c.Network.Gateway.Username) != "" {
		gwObj["username"] = c.Network.Gateway.Username
	}
	gwObj["password"] = c.Network.Gateway.Password
	if strings.TrimSpace(c.Network.Gateway.PasswordFile) != "" {
		gwObj["passwordFile"] = c.Network.Gateway.PasswordFile
	}
	gwObj["sshPrivateKey"] = c.Network.Gateway.SSHPrivateKey
	gwObj["sshPublicKey"] = c.Network.Gateway.SSHPublicKey
	if c.AutounattendPath != "" {
		doc["autounattendPath"] = c.AutounattendPath
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, append(out, '\n'), 0o644)
}

func (c *Config) persistSecretPaths(cfgPath string) error {
	return c.persistConfigSecrets(cfgPath)
}

// PreflightCredentials rejects shipped defaults and empty required secrets.
func (c *Config) PreflightCredentials() error {
	if c == nil {
		return fmt.Errorf("nil config")
	}
	var errs []string
	check := func(label, pw string, required bool) {
		if strings.TrimSpace(pw) == "" {
			if required {
				errs = append(errs, label+" password missing — run: .\\quarantine-vm.ps1 setup secrets")
			}
			return
		}
		if IsKnownDefaultPassword(pw) {
			errs = append(errs, label+" uses a known default password — run: .\\quarantine-vm.ps1 setup secrets")
		}
	}
	check("guest", c.Guest.Password, true)
	if strings.TrimSpace(c.Payload.Username) != "" {
		check("payload", c.Payload.Password, true)
	}
	if c.IsGatewayMode() || c.Network.Gateway.Enabled {
		check("gateway", c.Network.Gateway.Password, true)
		pub := strings.TrimSpace(c.Network.Gateway.SSHPublicKey)
		if pub == "" {
			pub = c.defaultGatewaySSHPublic()
		}
		if _, err := os.Stat(pub); err != nil {
			errs = append(errs, "gateway SSH public key missing — run: .\\quarantine-vm.ps1 setup secrets")
		}
	}
	unattend := strings.TrimSpace(c.AutounattendPath)
	if unattend != "" {
		if raw, err := os.ReadFile(unattend); err == nil {
			low := bytes.ToLower(raw)
			if bytes.Contains(low, []byte("changeme-quarantine")) || bytes.Contains(raw, []byte("__GUEST_PASSWORD__")) {
				errs = append(errs, "autounattend still contains a placeholder or ChangeMe-Quarantine! — run: .\\quarantine-vm.ps1 setup secrets")
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("credential preflight:\n  - %s", strings.Join(errs, "\n  - "))
}

// RenderUnattend fills templates/autounattend.xml placeholders with unique passwords.
func (c *Config) RenderUnattend(src, dest string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	guestUser := strings.TrimSpace(c.Guest.Username)
	if guestUser == "" {
		guestUser = DefaultGuestUsername
	}
	payloadUser := strings.TrimSpace(c.Payload.Username)
	if payloadUser == "" {
		payloadUser = DefaultPayloadUsername
	}
	repl := map[string]string{
		"__GUEST_USERNAME__":   xmlEscape(guestUser),
		"__GUEST_PASSWORD__":   xmlEscape(c.Guest.Password),
		"__PAYLOAD_USERNAME__": xmlEscape(payloadUser),
		"__PAYLOAD_PASSWORD__": xmlEscape(c.Payload.Password),
	}
	s := string(raw)
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	if strings.Contains(s, "__GUEST_PASSWORD__") || strings.Contains(strings.ToLower(s), "changeme-quarantine") {
		return fmt.Errorf("unattend render left a placeholder or known default")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(s), 0o600)
}

// RenderCloudInit writes a per-build user-data with hashed password and SSH key.
func (c *Config) RenderCloudInit(src, dest string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(c.Network.Gateway.SSHPublicKey)
	if err != nil {
		return fmt.Errorf("read gateway ssh public key: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(c.Network.Gateway.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := strings.TrimSpace(c.Network.Gateway.Username)
	if user == "" {
		user = "quarantine"
	}
	s := string(raw)
	s = strings.ReplaceAll(s, "__GATEWAY_USER__", user)
	s = strings.ReplaceAll(s, "__GATEWAY_PASSWORD_HASH__", string(hash))
	s = strings.ReplaceAll(s, "__GATEWAY_SSH_PUBKEY__", strings.TrimSpace(string(pub)))
	if strings.Contains(s, "plain_text_passwd: quarantine") || strings.Contains(s, "NOPASSWD:ALL") {
		return fmt.Errorf("cloud-init template still ships default password or NOPASSWD:ALL")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(s), 0o600)
}

func bigInt(n int) *big.Int {
	return big.NewInt(int64(n))
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
