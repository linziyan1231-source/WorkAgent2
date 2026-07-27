package chatgptproxy

import "testing"

func TestParseConversationSendIdentifiesConfiguredProAndDeduplicates(t *testing.T) {
	body := []byte(`{"action":"next","conversation_id":"conversation-123","messages":[{"id":"message-456","author":{"role":"user"}}],"model":"gpt-5-6-pro","thinking_effort":"standard","unknown":true}`)
	first, pro, err := ParseConversationSend(body, "user:7", []string{"gpt-5-6-pro"})
	if err != nil || !pro {
		t.Fatalf("parse Pro send: pro=%v err=%v", pro, err)
	}
	second, pro, err := ParseConversationSend(body, "user:7", []string{"gpt-5-6-pro"})
	if err != nil || !pro || first.LogicalID != second.LogicalID || len(first.LogicalID) != 64 || first.ThinkingEffort != "standard" {
		t.Fatalf("logical send was not stable: first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestParseConversationSendFailsClosedWithoutIdentityAnchor(t *testing.T) {
	body := []byte(`{"action":"next","messages":[{"id":"message-456"}],"model_slug":"gpt-5-6-pro"}`)
	if _, pro, err := ParseConversationSend(body, "user:7", []string{"gpt-5-6-pro"}); err == nil || pro {
		t.Fatalf("missing anchor was accepted: pro=%v err=%v", pro, err)
	}
}
