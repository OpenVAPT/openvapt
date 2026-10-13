package sign

import (
	"encoding/base64"
	"encoding/hex"
)

func hexs(b []byte) string { return hex.EncodeToString(b) }
func b64(b []byte) string  { return base64.StdEncoding.EncodeToString(b) }
