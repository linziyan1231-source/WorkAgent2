package chatgptproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderPortalUser      = "X-Llm-Web-Portal-User"
	HeaderPortalTimestamp = "X-Llm-Web-Portal-Timestamp"
	HeaderPortalSignature = "X-Llm-Web-Portal-Signature"
)

func DelegationHeaders(secret []byte, username, method, requestURI string, now time.Time) map[string]string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	user := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(username)))
	canonical := strings.Join([]string{strings.ToUpper(method), requestURI, timestamp, user}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return map[string]string{
		HeaderPortalUser:      user,
		HeaderPortalTimestamp: timestamp,
		HeaderPortalSignature: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
}
