package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"aionuiportal/internal/store"
)

type sharedEventHub struct {
	mu          sync.Mutex
	nextID      uint64
	subscribers map[uint64]chan store.SharedMessage
}

func newSharedEventHub() *sharedEventHub {
	return &sharedEventHub{subscribers: make(map[uint64]chan store.SharedMessage)}
}

func (h *sharedEventHub) subscribe() (uint64, <-chan store.SharedMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	channel := make(chan store.SharedMessage, 256)
	h.subscribers[h.nextID] = channel
	return h.nextID, channel
}

func (h *sharedEventHub) unsubscribe(id uint64) {
	h.mu.Lock()
	delete(h.subscribers, id)
	h.mu.Unlock()
}

func (h *sharedEventHub) publish(message store.SharedMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, channel := range h.subscribers {
		select {
		case channel <- message:
		default:
			// A slow client reconnects with Last-Event-ID and replays from the
			// database. Removing it prevents an unbounded memory queue.
			close(channel)
			delete(h.subscribers, id)
		}
	}
}

func (s *Server) publishSharedMessage(message store.SharedMessage) {
	if s.sharedEvents != nil && message.Seq > 0 {
		s.sharedEvents.publish(message)
	}
}

func (s *Server) publishSharedMessagesAfter(userID int64, conversationID string, after int64) {
	messages, err := s.store.ListSharedMessages(context.Background(), conversationID, userID, after, 100)
	if err != nil {
		s.logger.Printf("shared event replay failed conversation=%s after=%d: %v", conversationID, after, err)
		return
	}
	for _, message := range messages {
		s.publishSharedMessage(message)
	}
}

func (s *Server) sharedEventStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeProjectError(w, http.StatusUnauthorized, "SESSION_REQUIRED", "Portal session is required")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeProjectError(w, http.StatusInternalServerError, "SSE_UNAVAILABLE", "Shared event streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	subscriberID, events := s.sharedEvents.subscribe()
	defer s.sharedEvents.unsubscribe(subscriberID)
	lastID, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if lastID > 0 {
		for {
			messages, replayErr := s.store.ListSharedMessagesForUserAfter(r.Context(), session.User.ID, lastID, 200)
			if replayErr != nil {
				return
			}
			for _, message := range messages {
				if !writeSharedSSE(w, session.User.ID, message) {
					return
				}
				lastID = message.Seq
			}
			if len(messages) < 200 {
				break
			}
		}
		flusher.Flush()
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case message, open := <-events:
			if !open {
				return
			}
			if message.Seq <= lastID {
				continue
			}
			if _, accessErr := s.store.SharedConversationForUser(r.Context(), message.Conversation, session.User.ID); accessErr != nil {
				continue
			}
			if !writeSharedSSE(w, session.User.ID, message) {
				return
			}
			lastID = message.Seq
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSharedSSE(w http.ResponseWriter, currentUserID int64, message store.SharedMessage) bool {
	position := "left"
	if message.Kind == "system" {
		position = "center"
	} else if message.Kind == "user" && message.AuthorUserID != nil && *message.AuthorUserID == currentUserID {
		position = "right"
	}
	content := map[string]any{"content": message.Body}
	if message.Kind == "user" {
		content["teammateMessage"] = true
		content["senderName"] = message.AuthorName
		if message.AuthorUserID != nil {
			content["senderUserId"] = strconv.FormatInt(*message.AuthorUserID, 10)
		}
	}
	payload := map[string]any{
		"conversation_id": "shared:" + message.Conversation,
		"type":            "teammate_message",
		"msg_id":          message.ID,
		"created_at":      message.CreatedAt.UnixMilli(),
		"data": map[string]any{
			"id": message.ID, "msg_id": message.ID, "conversation_id": "shared:" + message.Conversation,
			"type": "text", "position": position, "status": "finish", "created_at": message.CreatedAt.UnixMilli(),
			"content": content,
		},
	}
	envelope, err := json.Marshal(map[string]any{"event": "message.stream", "payload": payload})
	if err != nil {
		return false
	}
	if _, err = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", message.Seq, envelope); err != nil {
		return false
	}
	if message.Kind != "assistant" && message.Kind != "system" {
		return true
	}
	completed, err := json.Marshal(map[string]any{
		"event": "turn.completed",
		"payload": map[string]any{
			"session_id": "shared:" + message.Conversation,
			"turn_id":    "shared-" + message.ID,
			"status":     "finished",
			"state":      "ai_waiting_input",
			"runtime": map[string]any{
				"state": "idle", "can_send_message": true, "has_task": false,
				"is_processing": false, "pending_confirmations": 0, "turn_id": nil,
			},
		},
	})
	if err != nil {
		return false
	}
	_, err = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", message.Seq, completed)
	return err == nil
}
