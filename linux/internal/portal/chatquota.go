package portal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/chatgptproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/httpjson"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const (
	maxChatGPTConversationBody = 16 * 1024 * 1024
	maxChatForwardQuotaBody    = 32 * 1024 * 1024
	chatForwardClockSkew       = 60 * time.Second
)

func (s *Server) chatGPTProEvents(writer http.ResponseWriter, request *http.Request) {
	userValue := request.Context().Value(userContextKey).(store.User)
	switch request.Method {
	case http.MethodGet:
		if request.URL.RawQuery != "" {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Event request does not accept query parameters"})
			return
		}
		events, err := s.store.PendingChatGPTProEvents(request.Context(), userValue.ID, 20)
		if err != nil {
			s.internalError(writer, "list ChatGPT Pro events", err)
			return
		}
		if events == nil {
			events = []store.ChatGPTProEvent{}
		}
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"events": events}})
	case http.MethodPost:
		var body struct {
			IDs []int64 `json:"ids"`
		}
		if err := httpjson.Decode(request, &body, 8*1024); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid event acknowledgement"})
			return
		}
		if err := s.store.AcknowledgeChatGPTProEvents(request.Context(), userValue.ID, body.IDs, s.now()); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid event acknowledgement"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"success": true})
	default:
		writer.Header().Set("Allow", "GET, POST")
		writeJSON(writer, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "Method not allowed"})
	}
}

func (s *Server) chatForwardQuotaReserve(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.authenticateChatForwardRequest(writer, request, maxChatForwardQuotaBody)
	if !ok {
		return
	}
	var input struct {
		UserID      int64  `json:"user_id"`
		RequestBody string `json:"request_body"`
	}
	if !decodeSingleJSON(body, &input) || input.UserID <= 0 || len(input.RequestBody) > maxChatGPTConversationBody {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "invalid_request", "message": "Invalid ChatGPT send"})
		return
	}
	userValue, err := s.store.UserByID(request.Context(), input.UserID)
	if err != nil || !userValue.Enabled {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "code": "invalid_user", "message": "ChatGPT user is unavailable"})
		return
	}
	send, pro, err := chatgptproxy.ParseConversationSend([]byte(input.RequestBody), strconv.FormatInt(input.UserID, 10), s.cfg.ChatForward.ProModels)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "invalid_request", "message": "Invalid ChatGPT send"})
		return
	}
	if !pro {
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "allowed": true, "pro": false})
		return
	}
	reservation, err := s.store.ReserveChatGPTPro(request.Context(), input.UserID, s.cfg.ChatForward.WeeklyProLimit, send.LogicalID, send.Model, send.ThinkingEffort, s.now())
	if err != nil {
		s.internalError(writer, "reserve ChatGPT Pro quota", err)
		return
	}
	response := map[string]any{"success": true, "allowed": false, "pro": true, "logical_id": send.LogicalID, "requested_model": send.Model,
		"used": reservation.Quota.Confirmed + reservation.Quota.Pending, "limit": reservation.Quota.Limit, "reset_at": reservation.Quota.ResetAt.Format(time.RFC3339)}
	switch reservation.State {
	case store.ChatGPTProReserved:
		response["allowed"] = true
	case store.ChatGPTProQuotaExceeded:
		response["code"], response["message"] = "chatgpt_pro_quota_exceeded", "ChatGPT Pro weekly quota is exhausted"
	case store.ChatGPTProDuplicatePending:
		response["code"], response["message"] = "chatgpt_pro_send_pending", "This ChatGPT Pro send is already pending review"
	case store.ChatGPTProDuplicateComplete:
		response["code"], response["message"] = "chatgpt_pro_send_already_processed", "This ChatGPT Pro send was already processed"
	default:
		writeJSON(writer, http.StatusInternalServerError, map[string]any{"success": false, "code": "quota_state_invalid", "message": "ChatGPT Pro quota state is invalid"})
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (s *Server) chatForwardQuotaSettle(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.authenticateChatForwardRequest(writer, request, maxChatForwardQuotaBody)
	if !ok {
		return
	}
	var input struct {
		UserID         int64  `json:"user_id"`
		LogicalID      string `json:"logical_id"`
		RequestedModel string `json:"requested_model"`
		UpstreamStatus int    `json:"upstream_status"`
		ResponseBody   string `json:"response_body"`
		ResponseBase64 bool   `json:"response_base64"`
		Failed         bool   `json:"failed"`
		ClosedEarly    bool   `json:"closed_early"`
	}
	if !decodeSingleJSON(body, &input) || input.UserID <= 0 || len(input.LogicalID) != 64 || strings.TrimSpace(input.RequestedModel) == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid ChatGPT Pro settlement"})
		return
	}
	status := store.ProStatusUnknown
	completed := false
	var models []string
	if input.Failed || input.UpstreamStatus < http.StatusOK || input.UpstreamStatus >= http.StatusMultipleChoices {
		status = store.ProStatusUpstreamRejected
	} else if !input.ClosedEarly {
		stream := []byte(input.ResponseBody)
		if input.ResponseBase64 {
			decoded, err := base64.StdEncoding.DecodeString(input.ResponseBody)
			if err != nil || len(decoded) > maxChatGPTConversationBody {
				stream = nil
			} else {
				stream = decoded
			}
		}
		if len(stream) <= maxChatGPTConversationBody {
			inspector := chatgptproxy.NewSSEInspector()
			inspector.Write(stream)
			outcome, summary := inspector.Outcome(input.RequestedModel, s.cfg.ChatForward.ProModels)
			completed, models = summary.Completed, summary.ServedModels
			status = map[string]string{chatgptproxy.OutcomeConfirmedPro: store.ProStatusConfirmed, chatgptproxy.OutcomeConfirmedFallback: store.ProStatusFallback, chatgptproxy.OutcomeUnknown: store.ProStatusUnknown}[outcome]
		}
	}
	if err := s.store.SettleChatGPTPro(request.Context(), input.UserID, input.LogicalID, status, input.UpstreamStatus, completed, models, s.now()); err != nil {
		s.internalError(writer, "settle ChatGPT Pro quota", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "status": status, "completed": completed, "served_models": models})
}

func (s *Server) authenticateChatForwardRequest(writer http.ResponseWriter, request *http.Request, limit int64) ([]byte, bool) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || s.chatForward == nil || len(s.chatForward.secret) < 32 {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	timestamp, err := strconv.ParseInt(request.Header.Get(headerChatForwardTimestamp), 10, 64)
	if err != nil {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	delta := s.now().Sub(time.Unix(timestamp, 0))
	if delta < -chatForwardClockSkew || delta > chatForwardClockSkew {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "ChatForward request is too large"})
		return nil, false
	}
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{request.Method, request.URL.Path, strconv.FormatInt(timestamp, 10), hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, s.chatForward.secret)
	_, _ = mac.Write([]byte(canonical))
	provided, err := base64.RawURLEncoding.DecodeString(request.Header.Get(headerChatForwardSignature))
	if err != nil || len(provided) != sha256.Size || !hmac.Equal(provided, mac.Sum(nil)) {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	if err := s.store.ConsumeChatForwardSignature(request.Context(), provided, s.now(), 2*chatForwardClockSkew); err != nil {
		if !errors.Is(err, store.ErrReplay) {
			s.logger.Printf("ChatForward authentication failed stage=replay_store")
		}
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	return body, true
}

func decodeSingleJSON(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(&struct{}{}) == io.EOF
}
