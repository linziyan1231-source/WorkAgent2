package portal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/chatgptproxy"
	"aionuiportal/internal/store"
)

const (
	maxChatGPTConversationBody = 16 * 1024 * 1024
	maxChatForwardQuotaBody    = 32 * 1024 * 1024
	chatForwardClockSkew       = 60 * time.Second
)

func (s *Server) chatGPTProEvents(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.RawQuery != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Event request does not accept query parameters"})
			return
		}
		events, err := s.store.PendingChatGPTProEvents(r.Context(), session.User.ID, 20)
		if err != nil {
			s.internalError(w, "list ChatGPT Pro events", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"events": events}})
	case http.MethodPost:
		if !s.validBrowserOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		var request struct {
			IDs []int64 `json:"ids"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid event acknowledgement"})
			return
		}
		if err := s.store.AcknowledgeChatGPTProEvents(r.Context(), session.User.ID, request.IDs, s.now()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid event acknowledgement"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) chatForwardQuotaReserve(w http.ResponseWriter, r *http.Request) {
	body, ok := s.authenticateChatForwardRequest(w, r, maxChatForwardQuotaBody)
	if !ok {
		return
	}
	var request struct {
		UserID      int64  `json:"user_id"`
		RequestBody string `json:"request_body"`
	}
	if !decodeSingleJSON(body, &request) || request.UserID <= 0 || len(request.RequestBody) > maxChatGPTConversationBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "invalid_request", "message": "Invalid ChatGPT send"})
		return
	}
	send, pro, err := chatgptproxy.ParseConversationSend([]byte(request.RequestBody), strconv.FormatInt(request.UserID, 10), s.cfg.ChatGPTProModels)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "invalid_request", "message": "Invalid ChatGPT send"})
		return
	}
	if !pro {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "allowed": true, "pro": false})
		return
	}
	reservation, err := s.store.ReserveChatGPTPro(r.Context(), request.UserID, send.LogicalID, send.Model, send.ThinkingEffort, s.now())
	if err != nil {
		s.internalError(w, "reserve ChatGPT Pro quota", err)
		return
	}
	response := map[string]any{
		"success": true, "allowed": false, "pro": true, "logical_id": send.LogicalID,
		"requested_model": send.Model, "used": reservation.Quota.Confirmed + reservation.Quota.Pending,
		"limit": reservation.Quota.Limit, "reset_at": reservation.Quota.ResetAt.Format(time.RFC3339),
	}
	switch reservation.State {
	case store.ChatGPTProReserved:
		response["allowed"] = true
	case store.ChatGPTProQuotaExceeded:
		response["code"] = "chatgpt_pro_quota_exceeded"
		response["message"] = "ChatGPT Pro weekly quota is exhausted"
	case store.ChatGPTProDuplicatePending:
		response["code"] = "chatgpt_pro_send_pending"
		response["message"] = "This ChatGPT Pro send is already pending review"
	case store.ChatGPTProDuplicateComplete:
		response["code"] = "chatgpt_pro_send_already_processed"
		response["message"] = "This ChatGPT Pro send was already processed"
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "quota_state_invalid", "message": "ChatGPT Pro quota state is invalid"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) chatForwardQuotaSettle(w http.ResponseWriter, r *http.Request) {
	body, ok := s.authenticateChatForwardRequest(w, r, maxChatForwardQuotaBody)
	if !ok {
		return
	}
	var request struct {
		UserID         int64  `json:"user_id"`
		LogicalID      string `json:"logical_id"`
		RequestedModel string `json:"requested_model"`
		UpstreamStatus int    `json:"upstream_status"`
		ResponseBody   string `json:"response_body"`
		ResponseBase64 bool   `json:"response_base64"`
		Failed         bool   `json:"failed"`
		ClosedEarly    bool   `json:"closed_early"`
	}
	if !decodeSingleJSON(body, &request) || request.UserID <= 0 || strings.TrimSpace(request.LogicalID) == "" || strings.TrimSpace(request.RequestedModel) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid ChatGPT Pro settlement"})
		return
	}
	status := store.ProStatusUnknown
	completed := false
	var models []string
	if request.Failed || request.UpstreamStatus < http.StatusOK || request.UpstreamStatus >= http.StatusMultipleChoices {
		status = store.ProStatusUpstreamRejected
	} else if !request.ClosedEarly {
		stream := []byte(request.ResponseBody)
		if request.ResponseBase64 {
			decoded, err := base64.StdEncoding.DecodeString(request.ResponseBody)
			if err == nil && len(decoded) <= maxChatGPTConversationBody {
				stream = decoded
			} else {
				stream = nil
			}
		}
		if len(stream) <= maxChatGPTConversationBody {
			inspector := chatgptproxy.NewSSEInspector()
			inspector.Write(stream)
			outcome, summary := inspector.Outcome(request.RequestedModel, s.cfg.ChatGPTProModels)
			completed, models = summary.Completed, summary.ServedModels
			status = map[string]string{
				chatgptproxy.OutcomeConfirmedPro:      store.ProStatusConfirmed,
				chatgptproxy.OutcomeConfirmedFallback: store.ProStatusFallback,
				chatgptproxy.OutcomeUnknown:           store.ProStatusUnknown,
			}[outcome]
		}
	}
	if err := s.store.SettleChatGPTPro(r.Context(), request.UserID, request.LogicalID, status, request.UpstreamStatus, completed, models, s.now()); err != nil {
		s.internalError(w, "settle ChatGPT Pro quota", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": status, "completed": completed, "served_models": models})
}

func (s *Server) authenticateChatForwardRequest(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return nil, false
	}
	if r.URL.RawQuery != "" || len(s.chatForwardSecret) < 32 {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	timestamp, err := strconv.ParseInt(r.Header.Get(headerChatForwardTimestamp), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	delta := s.now().Sub(time.Unix(timestamp, 0))
	if delta < -chatForwardClockSkew || delta > chatForwardClockSkew {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "ChatForward request is too large"})
		return nil, false
	}
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{r.Method, r.URL.Path, strconv.FormatInt(timestamp, 10), hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, s.chatForwardSecret)
	_, _ = mac.Write([]byte(canonical))
	provided, err := base64.RawURLEncoding.DecodeString(r.Header.Get(headerChatForwardSignature))
	if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "ChatForward authentication failed"})
		return nil, false
	}
	return body, true
}

func decodeSingleJSON(body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(&struct{}{}) == io.EOF
}
