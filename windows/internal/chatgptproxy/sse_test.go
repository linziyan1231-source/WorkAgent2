package chatgptproxy

import "testing"

func TestSSEInspectorConfirmsProOnlyFromServerMetadata(t *testing.T) {
	inspector := NewSSEInspector()
	inspector.Write([]byte("data: {\"type\":\"message\",\"model\":\"gpt-5-3-mini\"}\n"))
	inspector.Write([]byte("data: {\"type\":\"server_ste_metadata\",\"metadata\":{\"model_slug\":\"gpt-5-6-pro\"}}\n"))
	inspector.Write([]byte("data: [DONE]\n"))
	outcome, summary := inspector.Outcome("gpt-5-6-pro", []string{"gpt-5-6-pro"})
	if outcome != OutcomeConfirmedPro || len(summary.ServedModels) != 1 || summary.ServedModels[0] != "gpt-5-6-pro" {
		t.Fatalf("unexpected outcome: %s %+v", outcome, summary)
	}
}

func TestSSEInspectorDetectsExplicitFallbackAcrossChunks(t *testing.T) {
	inspector := NewSSEInspector()
	inspector.Write([]byte("data: {\"type\":\"server_ste_meta"))
	inspector.Write([]byte("data\",\"model\":\"gpt-5-3-mini\"}\r\ndata: {\"type\":\"message_stream_complete\"}\r\n"))
	outcome, _ := inspector.Outcome("gpt-5-6-pro", []string{"gpt-5-6-pro"})
	if outcome != OutcomeConfirmedFallback {
		t.Fatalf("fallback was not detected: %s", outcome)
	}
}

func TestSSEInspectorKeepsIncompleteStreamsUnknown(t *testing.T) {
	inspector := NewSSEInspector()
	inspector.Write([]byte("data: {\"type\":\"server_ste_metadata\",\"model\":\"gpt-5-6-pro\"}\n"))
	outcome, _ := inspector.Outcome("gpt-5-6-pro", []string{"gpt-5-6-pro"})
	if outcome != OutcomeUnknown {
		t.Fatalf("incomplete stream was classified as %s", outcome)
	}
}
