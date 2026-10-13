// Package sign makes reports tamper-evident with Ed25519 signatures.
//
// Honest scope: the key is generated on the user's own machine and kept
// there (~/.config/openvapt/report-key, mode 0600). A valid signature proves
// the report was not edited since the holder of that key produced it. It does
// NOT prove the machine is secure, and it is not an endorsement by the
// OpenVAPT project, which never sees reports or keys.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openvapt/openvapt/internal/report"
)

// KeyPath returns the default private key location.
func KeyPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "openvapt", "report-key")
}

// LoadOrCreateKey reads the private key, creating a new one if absent.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("key file %s is corrupt", path)
		}
		return ed25519.PrivateKey(raw), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// digest hashes the report's canonical JSON with Integrity removed.
func digest(r *report.Report) ([]byte, error) {
	cp := *r
	cp.Integrity = nil
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// KeyID is the first 16 hex characters of SHA-256(public key).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// Sign attaches an Integrity block to r.
func Sign(r *report.Report, priv ed25519.PrivateKey) error {
	d, err := digest(r)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	r.Integrity = &report.Integrity{
		Algorithm: "ed25519",
		SHA256:    hex.EncodeToString(d),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     KeyID(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d)),
	}
	return nil
}

// Verify checks r's Integrity block. If wantKeyID is not empty, the report
// must also be signed by that key (share your key id out of band).
func Verify(r *report.Report, wantKeyID string) error {
	in := r.Integrity
	if in == nil {
		return errors.New("report is not signed")
	}
	if in.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm %q", in.Algorithm)
	}
	pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	d, err := digest(r)
	if err != nil {
		return err
	}
	if hex.EncodeToString(d) != in.SHA256 {
		return errors.New("report content was modified after signing (digest mismatch)")
	}
	if !ed25519.Verify(pub, d, sig) {
		return errors.New("signature is invalid")
	}
	if wantKeyID != "" && KeyID(pub) != wantKeyID {
		return fmt.Errorf("signed by key %s, expected %s", KeyID(pub), wantKeyID)
	}
	return nil
}
