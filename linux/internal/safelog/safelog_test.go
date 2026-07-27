package safelog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriterEmitsJSONAndRedactsSecrets(t *testing.T) {
	var output bytes.Buffer
	writer := NewWriter(&output, "portal")
	input := "request failed authorization=Bearer abc.def api_key=topsecret https://example.test/cb?code=oauthcode"
	if _, err := writer.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	message, _ := record["message"].(string)
	for _, secret := range []string{"abc.def", "topsecret", "oauthcode"} {
		if strings.Contains(message, secret) {
			t.Fatalf("secret %q remained in log: %s", secret, message)
		}
	}
	if record["service"] != "portal" {
		t.Fatalf("unexpected record: %+v", record)
	}
}
