package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

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

// EnsureSecrets creates missing unique passwords and SSH keys, migrates inline
// non-default passwords into files, and writes unattend + cloud-init templates.
// Existing secret files are never overwritten.
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
		def  string
	}{
		{"guest", &c.Guest, c.defaultGuestPasswordFile()},
		{"payload", &c.Payload, c.defaultPayloadPasswordFile()},
	} {
		n, err := ensureAccountSecret(item.acc, item.def, generate)
		if err != nil {
			return "", fmt.Errorf("%s password: %w", item.name, err)
		}
		if n != "" {
			notes = append(notes, n)
		}
	}
	gw := &c.Network.Gateway
	if strings.TrimSpace(gw.PasswordFile) == "" {
		gw.PasswordFile = c.defaultGatewayPasswordFile()
	}
	n, err := ensurePasswordFile(&gw.Password, gw.PasswordFile, generate)
	if err != nil {
		return "", fmt.Errorf("gateway password: %w", err)
	}
	if n != "" {
		notes = append(notes, "gateway "+n)
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
	tmpl := strings.TrimSpace(c.AutounattendPath)
	if tmpl == "" {
		tmpl = filepath.Join(projectRoot, "templates", "autounattend.xml")
	}
	if _, err := os.Stat(tmpl); err == nil {
		if err := c.RenderUnattend(tmpl, unattendOut); err != nil {
			return "", err
		}
		c.AutounattendPath = unattendOut
		notes = append(notes, "rendered "+unattendOut)
	}
	cloudSrc := filepath.Join(projectRoot, "gateway", "cloud-init", "user-data")
	cloudOut := filepath.Join(c.DataDir(), "gateway", "user-data")
	if _, err := os.Stat(cloudSrc); err == nil {
		if err := c.RenderCloudInit(cloudSrc, cloudOut); err != nil {
			return "", err
		}
		notes = append(notes, "rendered "+cloudOut)
	}
	if err := c.persistSecretPaths(cfgPath); err != nil {
		return strings.Join(notes, "\n"), err
	}
	notes = append(notes, "updated config secret paths (passwords not stored in JSON)")
	return strings.Join(notes, "\n"), nil
}

func ensureAccountSecret(acc *AccountConfig, defPath string, generate bool) (string, error) {
	if strings.TrimSpace(acc.PasswordFile) == "" {
		acc.PasswordFile = defPath
	}
	return ensurePasswordFile(&acc.Password, acc.PasswordFile, generate)
}

func ensurePasswordFile(inline *string, path string, generate bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty password file path")
	}
	if raw, err := os.ReadFile(path); err == nil {
		pw := strings.TrimSpace(string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})))
		if pw != "" && !IsKnownDefaultPassword(pw) {
			*inline = pw
			return "", nil
		}
		if pw != "" && IsKnownDefaultPassword(pw) && !generate {
			*inline = pw
			return "", nil
		}
	}
	pw := strings.TrimSpace(*inline)
	if pw != "" && !IsKnownDefaultPassword(pw) {
		if err := writeSecretFile(path, pw); err != nil {
			return "", err
		}
		return "migrated inline password → " + path, nil
	}
	if !generate {
		return "", nil
	}
	next, err := GeneratePassword()
	if err != nil {
		return "", err
	}
	if err := writeSecretFile(path, next); err != nil {
		return "", err
	}
	*inline = next
	return "generated " + path, nil
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
	if c.Guest.PasswordFile == "" {
		c.Guest.PasswordFile = c.defaultGuestPasswordFile()
		dirty = true
	}
	if c.Payload.PasswordFile == "" {
		c.Payload.PasswordFile = c.defaultPayloadPasswordFile()
		dirty = true
	}
	if c.Network.Gateway.PasswordFile == "" {
		c.Network.Gateway.PasswordFile = c.defaultGatewayPasswordFile()
		dirty = true
	}
	if c.Network.Gateway.SSHPrivateKey == "" {
		c.Network.Gateway.SSHPrivateKey = c.defaultGatewaySSHPrivate()
		dirty = true
	}
	if c.Network.Gateway.SSHPublicKey == "" {
		c.Network.Gateway.SSHPublicKey = c.defaultGatewaySSHPublic()
		dirty = true
	}
	if _, err := os.Stat(c.Network.Gateway.SSHPrivateKey); err != nil {
		if werr := writeEd25519Keypair(c.Network.Gateway.SSHPrivateKey, c.Network.Gateway.SSHPublicKey); werr == nil {
			dirty = true
		}
	}
	for _, pair := range []struct {
		pw   *string
		file string
	}{
		{&c.Guest.Password, c.Guest.PasswordFile},
		{&c.Payload.Password, c.Payload.PasswordFile},
		{&c.Network.Gateway.Password, c.Network.Gateway.PasswordFile},
	} {
		if filePW, rerr := readSecretFile(pair.file); rerr == nil && filePW != "" {
			*pair.pw = filePW
			continue
		}
		if strings.TrimSpace(*pair.pw) != "" && !IsKnownDefaultPassword(*pair.pw) {
			if werr := writeSecretFile(pair.file, *pair.pw); werr == nil {
				dirty = true
			}
		}
	}
	return dirty, nil
}

func (c *Config) persistSecretPaths(cfgPath string) error {
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
	stripAccount := func(key string, acc AccountConfig) {
		obj, _ := doc[key].(map[string]any)
		if obj == nil {
			obj = map[string]any{}
			doc[key] = obj
		}
		obj["password"] = ""
		obj["passwordFile"] = acc.PasswordFile
	}
	stripAccount("guest", c.Guest)
	stripAccount("payload", c.Payload)
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
	gwObj["password"] = ""
	gwObj["passwordFile"] = c.Network.Gateway.PasswordFile
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
