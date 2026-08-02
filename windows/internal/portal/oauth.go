package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/store"
)

const (
	portalOAuthFlowTTL = 2 * time.Minute
	portalOAuthTimeout = 14 * time.Second
)

func (s *Server) mcpOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		ServerURL string `json:"server_url"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid OAuth login request"})
		return
	}
	serverURL, err := normalizeMCPServerURL(request.ServerURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	finish, err := s.instances.BeginRequest(session.User.WindowsSID, false)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance is draining"})
		return
	}
	defer finish()
	if _, err := s.instances.Ensure(r.Context(), session.User.WindowsSID); err != nil {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.start", "instance_failed", session, r, map[string]any{"reason": safeReason(err)})
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance could not be started"})
		return
	}
	route, err := s.instances.Route(r.Context(), session.User.WindowsSID)
	if err != nil || route.InstanceID == "" || !strings.EqualFold(route.Status.WindowsSID, session.User.WindowsSID) {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.start", "instance_failed", session, r, map[string]any{"reason": "route_unavailable"})
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance is unavailable"})
		return
	}
	state, err := auth.RandomToken(32)
	if err != nil {
		s.internalError(w, "generate MCP OAuth state", err)
		return
	}
	callback := *s.public
	callback.Path = "/api/mcp/oauth/callback"
	callback.RawPath, callback.RawQuery, callback.Fragment = "", "", ""
	oauthCtx, cancel := context.WithTimeout(r.Context(), portalOAuthTimeout)
	result, err := s.instances.OAuthStart(oauthCtx, session.User.WindowsSID, ipc.OAuthStartRequest{
		InstanceID: route.InstanceID, ServerURL: serverURL, State: state, RedirectURI: callback.String(),
	})
	cancel()
	if err != nil || !validPortalOAuthToken(result.FlowID, 32) || !validAuthorizationResult(result.AuthorizationURL, state) {
		if validPortalOAuthToken(result.FlowID, 32) {
			_ = s.instances.OAuthCancel(context.Background(), session.User.WindowsSID, ipc.OAuthCancelRequest{InstanceID: route.InstanceID, FlowID: result.FlowID, ServerURL: serverURL})
		}
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.start", "failed", session, r, map[string]any{"reason": "userhost_rejected"})
		writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "The MCP server OAuth flow could not be started"})
		return
	}
	now := s.now()
	binding := store.OAuthBinding{SessionTokenHash: session.TokenHash, WindowsSID: session.User.WindowsSID, InstanceID: route.InstanceID,
		FlowID: result.FlowID, Target: serverURL, ExpiresAt: now.Add(portalOAuthFlowTTL)}
	if err := s.store.CreateOAuthState(r.Context(), state, binding); err != nil {
		_ = s.instances.OAuthCancel(context.Background(), session.User.WindowsSID, ipc.OAuthCancelRequest{InstanceID: route.InstanceID, FlowID: result.FlowID, ServerURL: serverURL})
		s.internalError(w, "persist MCP OAuth state", err)
		return
	}
	if err := s.audit(r.Context(), "portal.mcp_oauth.start", "pending", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), nil); err != nil {
		_, _ = s.store.ConsumeOAuthState(context.Background(), state, session.TokenHash, s.now())
		_ = s.instances.OAuthCancel(context.Background(), session.User.WindowsSID, ipc.OAuthCancelRequest{InstanceID: route.InstanceID, FlowID: result.FlowID, ServerURL: serverURL})
		s.internalError(w, "audit MCP OAuth start", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": false, "pending": true, "error": "OAuth authorization is waiting for the browser popup",
		"authorization_url": result.AuthorizationURL, "state": state, "expires_in": int(portalOAuthFlowTTL.Seconds()),
	})
}

func (s *Server) mcpOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	state := r.URL.Query().Get("state")
	if !validPortalOAuthToken(state, 32) {
		s.writeOAuthResultPage(w, http.StatusBadRequest, "", false, "OAuth state is missing or invalid.")
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		s.writeOAuthResultPage(w, http.StatusUnauthorized, state, false, "The Portal session expired before OAuth completed.")
		return
	}
	binding, err := s.store.ConsumeOAuthState(r.Context(), state, session.TokenHash, s.now())
	if err != nil || !strings.EqualFold(binding.WindowsSID, session.User.WindowsSID) || !validPortalOAuthToken(binding.FlowID, 32) {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "invalid_state", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusBadRequest, state, false, "This OAuth callback is invalid, expired, or already used.")
		return
	}
	finish, err := s.instances.BeginRequest(binding.WindowsSID, false)
	if err != nil {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "instance_changed", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusServiceUnavailable, state, false, "The user instance changed before OAuth completed.")
		return
	}
	defer finish()
	route, err := s.instances.Route(r.Context(), binding.WindowsSID)
	if err != nil || route.InstanceID != binding.InstanceID || !strings.EqualFold(route.Status.WindowsSID, binding.WindowsSID) {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "instance_changed", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusServiceUnavailable, state, false, "The user instance changed before OAuth completed.")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		_ = s.instances.OAuthCancel(r.Context(), binding.WindowsSID, ipc.OAuthCancelRequest{InstanceID: binding.InstanceID, FlowID: binding.FlowID, ServerURL: binding.Target})
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "provider_denied", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusOK, state, false, "Authorization was denied by the OAuth provider.")
		return
	}
	code := r.URL.Query().Get("code")
	if len(code) == 0 || len(code) > 16*1024 || strings.IndexByte(code, 0) >= 0 {
		_ = s.instances.OAuthCancel(r.Context(), binding.WindowsSID, ipc.OAuthCancelRequest{InstanceID: binding.InstanceID, FlowID: binding.FlowID, ServerURL: binding.Target})
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "invalid_code", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusBadRequest, state, false, "The OAuth provider returned an invalid authorization code.")
		return
	}
	oauthCtx, cancel := context.WithTimeout(r.Context(), portalOAuthTimeout)
	err = s.instances.OAuthComplete(oauthCtx, binding.WindowsSID, ipc.OAuthCompleteRequest{InstanceID: binding.InstanceID, FlowID: binding.FlowID, ServerURL: binding.Target, Code: code})
	cancel()
	code = ""
	if err != nil {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.callback", "exchange_failed", session, r, nil)
		s.writeOAuthResultPage(w, http.StatusBadGateway, state, false, "The OAuth token exchange failed.")
		return
	}
	if err := s.audit(r.Context(), "portal.mcp_oauth.callback", "success", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), nil); err != nil {
		s.logger.Printf("MCP OAuth token was stored but success audit failed sid=%s", session.User.WindowsSID)
	}
	s.writeOAuthResultPage(w, http.StatusOK, state, true, "Authorization completed. You may close this window.")
}

func (s *Server) mcpOAuthCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var request struct {
		State string `json:"state"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validPortalOAuthToken(request.State, 32) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid OAuth cancellation request"})
		return
	}
	binding, err := s.store.ConsumeOAuthState(r.Context(), request.State, session.TokenHash, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}
	if err != nil {
		s.internalError(w, "consume cancelled MCP OAuth state", err)
		return
	}
	if !strings.EqualFold(binding.WindowsSID, session.User.WindowsSID) || !validPortalOAuthToken(binding.FlowID, 32) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "OAuth state did not match this Portal session"})
		return
	}
	if err := s.cancelOAuthBinding(r.Context(), binding); err != nil {
		s.auditBestEffort(r.Context(), "portal.mcp_oauth.cancel", "instance_failed", session, r, nil)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "OAuth state was invalidated, but the user instance could not be notified"})
		return
	}
	s.auditBestEffort(r.Context(), "portal.mcp_oauth.cancel", "success", session, r, nil)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) cancelOAuthBinding(ctx context.Context, binding store.OAuthBinding) error {
	finish, err := s.instances.BeginRequest(binding.WindowsSID, false)
	if err != nil {
		return err
	}
	defer finish()
	route, err := s.instances.Route(ctx, binding.WindowsSID)
	if err != nil {
		return err
	}
	if route.InstanceID != binding.InstanceID || !strings.EqualFold(route.Status.WindowsSID, binding.WindowsSID) {
		return errors.New("OAuth flow was bound to a different UserHost instance")
	}
	return s.instances.OAuthCancel(ctx, binding.WindowsSID, ipc.OAuthCancelRequest{InstanceID: binding.InstanceID, FlowID: binding.FlowID, ServerURL: binding.Target})
}

func (s *Server) mcpOAuthPopup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	channel := r.URL.Query().Get("channel")
	if !validPortalOAuthToken(channel, 16) {
		http.Error(w, "Invalid OAuth popup channel", http.StatusBadRequest)
		return
	}
	nonce, err := auth.RandomToken(18)
	if err != nil {
		s.internalError(w, "create OAuth popup CSP nonce", err)
		return
	}
	channelJSON, _ := json.Marshal(channel)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", oauthPageCSP(nonce))
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AionUi OAuth</title><style nonce="%s">body{font-family:Segoe UI,sans-serif;margin:3rem;color:#1d2129}p{max-width:36rem}</style></head><body><h1>Connecting OAuth</h1><p id="status">Preparing a secure authorization window…</p><script nonce="%s">(function(){"use strict";var id=%s;if(!("BroadcastChannel" in window)){document.getElementById("status").textContent="This browser does not support the secure OAuth popup channel.";return;}var channel=new BroadcastChannel("aionui-mcp-oauth-launch:"+id);var ready=setInterval(function(){channel.postMessage({type:"ready"});},500);channel.postMessage({type:"ready"});channel.onmessage=function(event){var value=event.data||{};if(value.type==="close"){clearInterval(ready);channel.close();window.close();return;}if(value.type!=="authorize"||typeof value.authorization_url!=="string"||typeof value.state!=="string"){return;}try{var target=new URL(value.authorization_url);if(target.protocol!=="https:"||target.searchParams.get("state")!==value.state){throw new Error("invalid authorization URL");}clearInterval(ready);channel.close();location.replace(target.href);}catch(_){document.getElementById("status").textContent="The OAuth authorization URL was rejected.";}};})();</script></body></html>`, nonce, nonce, channelJSON)
}

func (s *Server) mcpOAuthBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Length", fmt.Sprint(len(portalOAuthBridgeScript)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, portalOAuthBridgeScript)
	}
}

func (s *Server) writeOAuthResultPage(w http.ResponseWriter, status int, state string, success bool, message string) {
	nonce, err := auth.RandomToken(18)
	if err != nil {
		http.Error(w, "OAuth result could not be rendered", http.StatusInternalServerError)
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "aionui-portal-mcp-oauth-result", "state": state, "success": success, "error": func() string {
		if success {
			return ""
		}
		return message
	}()})
	messageJSON, _ := json.Marshal(message)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", oauthPageCSP(nonce))
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AionUi OAuth</title><style nonce="%s">body{font-family:Segoe UI,sans-serif;margin:3rem;color:#1d2129}p{max-width:36rem}</style></head><body><h1>OAuth authorization</h1><p id="status"></p><script nonce="%s">(function(){"use strict";history.replaceState(null,"","/api/mcp/oauth/callback");var payload=%s;document.getElementById("status").textContent=%s;if(payload.state&&("BroadcastChannel" in window)){var channel=new BroadcastChannel("aionui-mcp-oauth-result:"+payload.state);channel.postMessage(payload);setTimeout(function(){channel.postMessage(payload);channel.close();window.close();},200);}})();</script></body></html>`, nonce, nonce, payload, messageJSON)
}

func oauthPageCSP(nonce string) string {
	return fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nonce, nonce)
}

func normalizeMCPServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("MCP server URL is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("MCP server URL must be HTTPS and must not contain credentials, query, or fragment")
	}
	return raw, nil
}

func validAuthorizationResult(raw, state string) bool {
	if len(raw) == 0 || len(raw) > 16*1024 {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && parsed.Query().Get("state") == state
}

func validPortalOAuthToken(value string, size int) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	auth.Zero(decoded)
	return len(decoded) == size
}

func (s *Server) auditBestEffort(ctx context.Context, action, outcome string, session store.Session, r *http.Request, details map[string]any) {
	if err := s.audit(ctx, action, outcome, session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), details); err != nil {
		s.logger.Printf("MCP OAuth audit failure action=%s outcome=%s sid=%s", action, outcome, session.User.WindowsSID)
	}
}

const portalOAuthBridgeScript = `(function () {
  "use strict";
  if (window.__aionuiPortalOAuthBridge) return;
  window.__aionuiPortalOAuthBridge = true;
  var nativeFetch = window.fetch.bind(window);

  function jsonResult(success, error) {
    return new Response(JSON.stringify({ success: success, error: error || undefined }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8" }
    });
  }

  function randomChannel() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function requestDetails(input, init) {
    var raw = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    var method = init && init.method ? init.method : (input instanceof Request ? input.method : "GET");
    return { url: new URL(raw, location.href), method: String(method).toUpperCase() };
  }

  async function cancelState(state) {
    try {
      await nativeFetch("/api/mcp/oauth/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ state: state }),
        keepalive: true
      });
    } catch (_) {}
  }

  async function runOAuth(input, init) {
    if (!("BroadcastChannel" in window) || !window.crypto || !crypto.getRandomValues) {
      return jsonResult(false, "This browser does not support the secure OAuth popup flow.");
    }
    var channelID = randomChannel();
    var launch = new BroadcastChannel("aionui-mcp-oauth-launch:" + channelID);
    var readyResolve;
    var ready = new Promise(function (resolve) { readyResolve = resolve; });
    launch.onmessage = function (event) {
      if (event.data && event.data.type === "ready") readyResolve(true);
    };
    window.open("/api/mcp/oauth/popup?channel=" + encodeURIComponent(channelID), "_blank", "popup,width=720,height=760,noopener,noreferrer");
    var popupReady = await Promise.race([ready, new Promise(function (resolve) { setTimeout(function () { resolve(false); }, 4000); })]);
    if (!popupReady) {
      launch.close();
      return jsonResult(false, "The OAuth popup was blocked. Allow popups for this Portal and try again.");
    }

    var response;
    try {
      response = await nativeFetch(input, init);
    } catch (error) {
      launch.postMessage({ type: "close" });
      setTimeout(function () { launch.close(); }, 500);
      throw error;
    }
    if (!response.ok) {
      launch.postMessage({ type: "close" });
      setTimeout(function () { launch.close(); }, 500);
      return response;
    }
    var start;
    try {
      start = await response.json();
    } catch (_) {
      launch.postMessage({ type: "close" });
      setTimeout(function () { launch.close(); }, 500);
      return jsonResult(false, "The Portal returned an invalid OAuth start response.");
    }
    if (!start || start.pending !== true || typeof start.state !== "string" || typeof start.authorization_url !== "string") {
      launch.postMessage({ type: "close" });
      setTimeout(function () { launch.close(); }, 500);
      return jsonResult(false, "The Portal could not start OAuth authorization.");
    }
    try {
      var authorizationURL = new URL(start.authorization_url);
      if (authorizationURL.protocol !== "https:" || authorizationURL.searchParams.get("state") !== start.state) throw new Error("invalid");
    } catch (_) {
      await cancelState(start.state);
      launch.postMessage({ type: "close" });
      setTimeout(function () { launch.close(); }, 500);
      return jsonResult(false, "The OAuth authorization URL was rejected.");
    }

    var resultChannel = new BroadcastChannel("aionui-mcp-oauth-result:" + start.state);
    var completion = new Promise(function (resolve) {
      var timer = setTimeout(function () { resolve({ timeout: true }); }, 125000);
      resultChannel.onmessage = function (event) {
        var value = event.data || {};
        if (value.type !== "aionui-portal-mcp-oauth-result" || value.state !== start.state || typeof value.success !== "boolean") return;
        clearTimeout(timer);
        resolve({ success: value.success, error: typeof value.error === "string" ? value.error.slice(0, 512) : undefined });
      };
    });
    launch.postMessage({ type: "authorize", authorization_url: start.authorization_url, state: start.state });
    setTimeout(function () { launch.close(); }, 5000);
    var result = await completion;
    resultChannel.close();
    if (result.timeout) {
      await cancelState(start.state);
      return jsonResult(false, "OAuth authorization timed out. Please try again.");
    }
    return jsonResult(result.success, result.error);
  }

  window.fetch = function (input, init) {
    try {
      var details = requestDetails(input, init);
      if (details.url.origin === location.origin && details.url.pathname === "/api/mcp/oauth/login" && details.url.search === "" && details.method === "POST") {
        return runOAuth(input, init);
      }
    } catch (_) {}
    return nativeFetch(input, init);
  };
})();
`
