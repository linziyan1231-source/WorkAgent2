package chatgptproxy

import "testing"

func TestSSEInspectorConfirmsProAndDetectsFallback(t *testing.T) {
	inspector := NewSSEInspector()
	inspector.Write([]byte("data: {\"type\":\"server_ste_meta"))
	inspector.Write([]byte("data\",\"model_slug\":\"gpt-5-6-pro\"}\r\ndata: [DONE]\r\n"))
	outcome, summary := inspector.Outcome("gpt-5-6-pro", []string{"gpt-5-6-pro"})
	if outcome != OutcomeConfirmedPro || !summary.Completed || len(summary.ServedModels) != 1 {
		t.Fatalf("unexpected Pro outcome: %s %+v", outcome, summary)
	}
	inspector = NewSSEInspector()
	inspector.Write([]byte("data: {\"type\":\"server_ste_metadata\",\"model\":\"gpt-5-mini\"}\n\ndata: {\"type\":\"message_stream_complete\"}\n"))
	if outcome, _ := inspector.Outcome("gpt-5-6-pro", []string{"gpt-5-6-pro"}); outcome != OutcomeConfirmedFallback {
		t.Fatalf("fallback was classified as %s", outcome)
	}
}
