//go:build windows

package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"vt-audit/agent/pkg/enroll"
	"vt-audit/agent/pkg/tlsclient"
)

/*
Changes:
- Store creds in ProgramFiles\VT Agent\creds.bin so that service (running from System32) always writes in a stable location.
- Keep DPAPI protect/unprotect.
- Keep 'Poll' (server-controlled), so main can loop correctly without any agent-side interval flag.
*/

type creds struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	Poll        int    `json:"poll"`
}

func dataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("Program Files"); pd != "" {
			return filepath.Join(pd, "VT Agent")
		}
	}
	return "data"
}

func credsPath() (string, error) {
	base := dataDir()
	if base == "" {
		return "", errors.New("dataDir not found")
	}
	return filepath.Join(base, "creds.bin"), nil
}

func saveCreds(c creds) error {
	p, err := credsPath()
	if err != nil { return err }
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { return err }
	plain, _ := json.Marshal(c)
	enc, err := dpapiProtect(plain)
	if err != nil { return err }
	return os.WriteFile(p, enc, 0o600)
}

func loadCreds() (creds, error) {
	p, err := credsPath()
	if err != nil { return creds{}, err }
	b, err := os.ReadFile(p)
	if err != nil { return creds{}, err }
	plain, err := dpapiUnprotect(b)
	if err != nil { return creds{}, err }
	var c creds
	if err := json.Unmarshal(plain, &c); err != nil { return creds{}, err }
	return c, nil
}

// LoadOrEnroll: read cache; if missing then enroll & persist (DPAPI).
func LoadOrEnroll(httpClient *tlsclient.Client, serverURL, enrollKey string) (agentID, agentSecret string, poll int) {
	if c, err := loadCreds(); err == nil && c.AgentID != "" && c.AgentSecret != "" {
		return c.AgentID, c.AgentSecret, c.Poll
	}
	fp := fingerprint()
	aid, sec, p, err := enroll.Enroll(httpClient, serverURL, enrollKey, enroll.Request{Fingerprint: fp})
	if err != nil { panic(err) }
	_ = saveCreds(creds{AgentID: aid, AgentSecret: sec, Poll: p})
	return aid, sec, p
}

// LoadCredentials: read cache only (for local audits). Return empty if not present.
func LoadCredentials() (agentID, agentSecret string, poll int) {
	if c, err := loadCreds(); err == nil {
		return c.AgentID, c.AgentSecret, c.Poll
	}
	return "", "", 0
}

// fingerprint: MachineGuid -> SHA256 (simple & stable)
func fingerprint() string {
	mg := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
	h := sha256.Sum256([]byte(mg))
	return hex.EncodeToString(h[:])
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil { return "" }
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil { return "" }
	return v
}

/* ----- DPAPI wrappers ----- */

func dpapiProtect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	in := windows.DataBlob{Size: uint32(len(plain))}
	if len(plain) > 0 { in.Data = &plain[0] }
	err := windows.CryptProtectData(&in, windows.StringToUTF16Ptr("vt-agent"), nil, 0, nil, 0, &out)
	if err != nil { return nil, err }
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	b := make([]byte, out.Size)
	if out.Size > 0 && out.Data != nil {
		copy(b, unsafe.Slice(out.Data, out.Size))
	}
	return b, nil
}

func dpapiUnprotect(enc []byte) ([]byte, error) {
	var out windows.DataBlob
	in := windows.DataBlob{Size: uint32(len(enc))}
	if len(enc) > 0 { in.Data = &enc[0] }
	var desc *uint16
	err := windows.CryptUnprotectData(&in, &desc, nil, 0, nil, 0, &out)
	if err != nil { return nil, err }
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	b := make([]byte, out.Size)
	if out.Size > 0 && out.Data != nil {
		copy(b, unsafe.Slice(out.Data, out.Size))
	}
	return b, nil
}
