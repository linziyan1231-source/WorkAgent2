package portal

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/store"
)

func TestWriteSharedSSECompletesRuntimeAfterAssistantMessage(t *testing.T) {
	recorder := httptest.NewRecorder()
	authorID := int64(1)
	message := store.SharedMessage{Seq: 7, ID: "reply", Conversation: "conversation", Kind: "assistant", AuthorUserID: &authorID, Body: "done", CreatedAt: time.Unix(1, 0)}
	if !writeSharedSSE(recorder, 1, message) {
		t.Fatal("writeSharedSSE returned false")
	}
	var events []map[string]any
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 2 || events[0]["event"] != "message.stream" || events[1]["event"] != "turn.completed" {
		t.Fatalf("events=%v", events)
	}
	payload := events[1]["payload"].(map[string]any)
	runtime := payload["runtime"].(map[string]any)
	if payload["session_id"] != "shared:conversation" || runtime["is_processing"] != false || runtime["has_task"] != false {
		t.Fatalf("completion payload=%v", payload)
	}
	messagePayload := events[0]["payload"].(map[string]any)
	messageData := messagePayload["data"].(map[string]any)
	if messageData["position"] != "left" {
		t.Fatalf("assistant message position=%v", messageData["position"])
	}
}

func TestWriteSharedSSEIncludesUserAuthorMetadata(t *testing.T) {
	recorder := httptest.NewRecorder()
	authorID := int64(17)
	message := store.SharedMessage{Seq: 8, ID: "user-message", Conversation: "conversation", Kind: "user", AuthorUserID: &authorID, AuthorName: "Alice", Body: "hello", CreatedAt: time.Unix(2, 0)}
	if !writeSharedSSE(recorder, authorID, message) {
		t.Fatal("writeSharedSSE returned false")
	}
	var envelope map[string]any
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.HasPrefix(line, "data: ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &envelope); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	payload := envelope["payload"].(map[string]any)
	data := payload["data"].(map[string]any)
	content := data["content"].(map[string]any)
	if data["position"] != "right" || content["senderName"] != "Alice" || content["senderUserId"] != "17" || content["teammateMessage"] != true {
		t.Fatalf("user event metadata=%v", data)
	}
}
