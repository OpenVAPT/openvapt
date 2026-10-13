// Package sign makes reports tamper-evident with Ed25519 signatures.
//
// Honest scope: the key is generated on the user's own machine and kept
// there (~/.config/openvapt/report-key, mode 0600). A valid signature shows
// the report was not edited since the holder of that key produced it. It does
// NOT prove the machine is secure, and it is not an endorsement by the
// OpenVAPT project, which never sees reports or keys.
//
// What is signed: the exact bytes of report.json without its integrity block
// (report.CanonicalJSON). Verification decodes the file strictly, rebuilds
// the canonical JSON and requires the file to match it byte for byte, so an
// added field, a duplicate key or a key in another letter case fails.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/openvapt/openvapt/internal/report"
)

// Format is the current digest format recorded in report.Integrity.Format.
const Format = "openvapt.sign/2"

// ErrNoConfigDir means there is no per-user configuration folder, so there
// is no private place to keep a key. Reports are then left unsigned rather
// than keeping a key in a shared folder such as /tmp.
var ErrNoConfigDir = errors.New("no user configuration folder to keep a private signing key in")

// KeyPath returns the default private key location.
func KeyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" || !filepath.IsAbs(dir) {
		return "", ErrNoConfigDir
	}
	return filepath.Join(dir, "openvapt", "report-key"), nil
}

// LoadOrCreateKey reads the private key, creating a new one if absent. The
// key folder must be a real directory (not a symlink) owned by the effective
// user with mode 0700, and the key a regular file owned by that user that
// group and others cannot access. A new key is created exclusively, without
// following symlinks.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkPrivate(dir, true); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		return loadKey(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := createExclusive(path)
	if err != nil {
		return nil, err
	}
	_, err = f.Write([]byte(base64.StdEncoding.EncodeToString(priv)))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	if err := checkPrivate(path, false); err != nil {
		return nil, err
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key file %s is corrupt", path)
	}
	return ed25519.PrivateKey(raw), nil
}

// checkPrivate requires p to be a non-symlink directory (or regular file),
// owned by the effective user, with no group or other permissions.
func checkPrivate(p string, wantDir bool) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it for the signing key", p)
	}
	if wantDir && !st.IsDir() || !wantDir && !st.Mode().IsRegular() {
		return fmt.Errorf("%s has the wrong file type for the signing key", p)
	}
	if strictPerms && st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others (chmod go-rwx)", p)
	}
	if !ownedByEUID(st) {
		return fmt.Errorf("%s is not owned by the effective user", p)
	}
	return nil
}

// digest is SHA-256 of the canonical report bytes for the given format.
func digest(r *report.Report, format string) ([]byte, error) {
	var b []byte
	var err error
	switch format {
	case Format:
		b, err = r.CanonicalJSON()
	case "":
		// Earlier releases hashed the compact JSON of the report.
		cp := *r
		cp.Integrity = nil
		b, err = json.Marshal(&cp)
	default:
		return nil, fmt.Errorf("cannot verify: unknown signature format %q", format)
	}
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

// Sign attaches an Integrity block to r. The digest covers the exact bytes
// of r.CanonicalJSON(), which report.json reproduces with the block added.
func Sign(r *report.Report, priv ed25519.PrivateKey) error {
	r.Integrity = nil
	d, err := digest(r, Format)
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
		Format:    Format,
	}
	return nil
}

// VerifyBytes checks a report.json file exactly as stored. It decodes the
// bytes strictly (no unknown fields, duplicate keys or letter case variants),
// requires them to be the canonical JSON of the decoded report (one trailing
// newline is tolerated), and then checks the signature. Older formats that
// cannot be checked this way are reported as such, never as a mismatch.
func VerifyBytes(b []byte, wantKeyID string) (*report.Report, error) {
	r, err := report.ParseStrict(b)
	if err != nil {
		var probe struct {
			Schema    string          `json:"schema"`
			Integrity json.RawMessage `json:"integrity"`
		}
		if json.Unmarshal(b, &probe) == nil && probe.Schema != "" && probe.Schema != report.SchemaVersion && len(probe.Integrity) > 0 {
			return nil, fmt.Errorf("cannot verify: signed with an older report format (%s); re-run the scan with this version to get a verifiable report", probe.Schema)
		}
		return nil, err
	}
	if r.Integrity == nil {
		return nil, errors.New("report is not signed")
	}
	if r.Schema != report.SchemaVersion {
		return nil, fmt.Errorf("cannot verify: signed with an older report format (%s); re-run the scan with this version to get a verifiable report", r.Schema)
	}
	canon, err := r.JSON()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b, canon) && !bytes.Equal(b, append(canon, '\n')) {
		return nil, errors.New("report file was modified after signing (it is not the exact file that was signed)")
	}
	if err := Verify(r, wantKeyID); err != nil {
		return nil, err
	}
	return r, nil
}

// VerifyFile reads path (at most report.MaxReportSize bytes) and calls
// VerifyBytes.
func VerifyFile(path string, wantKeyID string) (*report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, report.MaxReportSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > report.MaxReportSize {
		return nil, errors.New("report file is too large")
	}
	return VerifyBytes(b, wantKeyID)
}

// Verify checks the Integrity block of an in-memory report. If wantKeyID is
// not empty, the report must also be signed by that key (share your key id
// out of band). To check a file, use VerifyFile, which also proves the file
// bytes are exactly what was signed.
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
	d, err := digest(r, in.Format)
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
