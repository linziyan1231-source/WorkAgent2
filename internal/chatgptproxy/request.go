package chatgptproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type Send struct {
	ConversationID  string
	LogicalID       string
	MessageID       string
	Model           string
	ParentMessageID string
	ThinkingEffort  string
}

type conversationRequest struct {
	Action          string `json:"action"`
	ConversationID  string `json:"conversation_id"`
	Model           string `json:"model"`
	ModelSlug       string `json:"model_slug"`
	ParentMessageID string `json:"parent_message_id"`
	ThinkingEffort  string `json:"thinking_effort"`
	Messages        []struct {
		ID     string `json:"id"`
		Author *struct {
			Role string `json:"role"`
		} `json:"author"`
	} `json:"messages"`
}

func ParseConversationSend(body []byte, userKey string, configuredProModels []string) (Send, bool, error) {
	var request conversationRequest
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&request); err != nil {
		return Send{}, false, errors.New("invalid ChatGPT conversation request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Send{}, false, errors.New("multiple ChatGPT conversation request values")
	}
	if request.Action != "next" || len(request.Messages) == 0 {
		return Send{}, false, nil
	}
	messageID := ""
	for index := len(request.Messages) - 1; index >= 0; index-- {
		message := request.Messages[index]
		if strings.TrimSpace(message.ID) == "" {
			continue
		}
		if message.Author == nil || strings.EqualFold(message.Author.Role, "user") {
			messageID = strings.TrimSpace(message.ID)
			break
		}
	}
	if messageID == "" {
		return Send{}, false, nil
	}
	model := strings.TrimSpace(request.ModelSlug)
	if model == "" {
		model = strings.TrimSpace(request.Model)
	}
	if !IsProModel(model, configuredProModels) {
		return Send{}, false, nil
	}
	conversationID := strings.TrimSpace(request.ConversationID)
	parentMessageID := strings.TrimSpace(request.ParentMessageID)
	anchor := conversationID
	if anchor == "" {
		anchor = parentMessageID
	}
	if strings.TrimSpace(userKey) == "" || anchor == "" {
		return Send{}, false, errors.New("ChatGPT Pro send is missing an identity anchor")
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{userKey, anchor, messageID}, "\x00")))
	return Send{
		ConversationID:  conversationID,
		LogicalID:       hex.EncodeToString(digest[:]),
		MessageID:       messageID,
		Model:           model,
		ParentMessageID: parentMessageID,
		ThinkingEffort:  strings.TrimSpace(request.ThinkingEffort),
	}, true, nil
}

func IsProModel(model string, configured []string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" {
		return false
	}
	for _, candidate := range configured {
		if strings.EqualFold(strings.TrimSpace(candidate), model) {
			return true
		}
	}
	return false
}
