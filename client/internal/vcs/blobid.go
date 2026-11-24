package vcs

import (
	"encoding/hex"
	"strings"
)

func BlobID(root string,
	rel string,
	content []byte) string {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(rel) == "" {
		return ""
	}
	out, err := gitIn(root, content, "hash-object", "--stdin", "--path="+rel)
	if err != nil {
		return ""
	}
	return validBlobID(strings.TrimSpace(out))
}

func validBlobID(id string) string {
	if len(id) != 40 && len(id) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return strings.ToLower(id)
}
