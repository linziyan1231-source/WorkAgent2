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

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/httpjson"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const portalOAuthTTL = 2 * time.Minute

type portalOAuthStartResult struct {
	AuthorizationURL string `json:"authorization_url"`
	FlowID           string `json:"flow_id"`
}

type runtimeIdentityStatus struct {
	TenantID  string    `json:"tenant_id"`
	Ready     bool      `json:"ready"`
	StartedAt time.Time `json:"started_at"`
}

func (s *Server) mcpOAuthStart(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ServerURL string `json:"server_url"`
	}
	if err := httpjson.Decode(request, &body, 16*1024); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid OAuth login request"})
		return
	}
	serverURL, err := normalizeMCPServerURL(body.ServerURL)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	session := request.Context().Value(sessionContextKey).(store.Session)
	if err := s.ensureRuntime(request.Context(), session.User); err != nil {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.start", "instance_failed", map[string]any{"reason": "startup_failed"})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Tenant runtime is unavailable"})
		return
	}
	var runtimeStatus runtimeIdentityStatus
	if err := s.callRuntimeControl(request.Context(), session.User, http.MethodGet, "/internal/status", nil, &runtimeStatus); err != nil || !runtimeStatus.Ready || runtimeStatus.TenantID != session.User.TenantID || runtimeStatus.StartedAt.IsZero() {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.start", "instance_failed", map[string]any{"reason": "route_unavailable"})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Tenant runtime identity is unavailable"})
		return
	}
	state, err := auth.RandomToken(32)
	if err != nil {
		s.internalError(writer, "create OAuth state", err)
		return
	}
	callback := s.publicOrigin + "/api/mcp/oauth/callback"
	var result portalOAuthStartResult
	control := map[string]string{"server_url": serverURL, "state": state, "redirect_uri": callback}
	oauthContext, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	err = s.callRuntimeControl(oauthContext, session.User, http.MethodPost, "/internal/oauth/start", control, &result)
	cancel()
	if err != nil || !validPortalOAuthToken(result.FlowID, 32) || !validAuthorizationResult(result.AuthorizationURL, state) {
		if validPortalOAuthToken(result.FlowID, 32) {
			_ = s.callRuntimeControl(context.Background(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": result.FlowID, "server_url": serverURL}, nil)
		}
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.start", "failed", map[string]any{"reason": "userhost_rejected"})
		writeJSON(writer, http.StatusBadGateway, map[string]any{"success": false, "message": "OAuth authorization could not be started"})
		return
	}
	now := s.now()
	binding := store.OAuthBinding{SessionTokenHash: session.TokenHash, TenantID: session.User.TenantID, RuntimeStartedAt: runtimeStatus.StartedAt.UTC().Format(time.RFC3339Nano), FlowID: result.FlowID, Target: serverURL, ExpiresAt: now.Add(portalOAuthTTL)}
	if err := s.store.CreateOAuthState(request.Context(), state, binding, now); err != nil {
		_ = s.callRuntimeControl(context.Background(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": result.FlowID, "server_url": serverURL}, nil)
		s.internalError(writer, "persist OAuth state", err)
		return
	}
	remoteIP, _ := request.Context().Value(remoteIPContextKey).(string)
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.mcp_oauth.start", Outcome: "pending", Username: session.User.Username, TenantID: session.User.TenantID, RemoteIP: remoteIP}); err != nil {
		_, _ = s.store.ConsumeOAuthState(context.Background(), state, session.TokenHash, s.now())
		_ = s.callRuntimeControl(context.Background(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": result.FlowID, "server_url": serverURL}, nil)
		s.internalError(writer, "audit OAuth start", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"success": false, "pending": true, "authorization_url": result.AuthorizationURL, "state": state, "expires_in": int(portalOAuthTTL.Seconds())})
}

func (s *Server) mcpOAuthCallback(writer http.ResponseWriter, request *http.Request) {
	state := request.URL.Query().Get("state")
	if !validPortalOAuthToken(state, 32) {
		s.writeOAuthResultPage(writer, http.StatusBadRequest, "", false, "OAuth state is missing or invalid.")
		return
	}
	session, err := s.sessionForRequest(request)
	if err != nil {
		s.writeOAuthResultPage(writer, http.StatusUnauthorized, state, false, "The Portal session expired before OAuth completed.")
		return
	}
	binding, err := s.store.ConsumeOAuthState(request.Context(), state, session.TokenHash, s.now())
	if err != nil || binding.TenantID != session.User.TenantID || !validPortalOAuthToken(binding.FlowID, 32) {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "invalid_state", nil)
		s.writeOAuthResultPage(writer, http.StatusBadRequest, state, false, "This OAuth callback is invalid, expired, or already used.")
		return
	}
	if err := s.ensureRuntime(request.Context(), session.User); err != nil {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "instance_changed", nil)
		s.writeOAuthResultPage(writer, http.StatusServiceUnavailable, state, false, "The tenant runtime changed before OAuth completed.")
		return
	}
	var runtimeStatus runtimeIdentityStatus
	if err := s.callRuntimeControl(request.Context(), session.User, http.MethodGet, "/internal/status", nil, &runtimeStatus); err != nil || runtimeStatus.StartedAt.UTC().Format(time.RFC3339Nano) != binding.RuntimeStartedAt {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "instance_changed", nil)
		s.writeOAuthResultPage(writer, http.StatusServiceUnavailable, state, false, "The tenant runtime changed before OAuth completed.")
		return
	}
	if request.URL.Query().Get("error") != "" {
		_ = s.callRuntimeControl(request.Context(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": binding.FlowID, "server_url": binding.Target}, nil)
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "provider_denied", nil)
		s.writeOAuthResultPage(writer, http.StatusOK, state, false, "Authorization was denied by the OAuth provider.")
		return
	}
	code := request.URL.Query().Get("code")
	if code == "" || len(code) > 16*1024 || strings.IndexByte(code, 0) >= 0 {
		_ = s.callRuntimeControl(request.Context(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": binding.FlowID, "server_url": binding.Target}, nil)
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "invalid_code", nil)
		s.writeOAuthResultPage(writer, http.StatusBadRequest, state, false, "The OAuth provider returned an invalid authorization code.")
		return
	}
	completion := map[string]string{"flow_id": binding.FlowID, "server_url": binding.Target, "code": code}
	oauthContext, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	err = s.callRuntimeControl(oauthContext, session.User, http.MethodPost, "/internal/oauth/complete", completion, nil)
	cancel()
	code, completion["code"] = "", ""
	if err != nil {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.callback", "exchange_failed", nil)
		s.writeOAuthResultPage(writer, http.StatusBadGateway, state, false, "The OAuth token exchange failed.")
		return
	}
	remoteIP, _ := request.Context().Value(remoteIPContextKey).(string)
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: s.now(), Action: "portal.mcp_oauth.callback", Outcome: "success", Username: session.User.Username, TenantID: session.User.TenantID, RemoteIP: remoteIP}); err != nil {
		s.logger.Printf("OAuth token persisted but success audit failed tenant=%s", session.User.TenantID)
	}
	s.writeOAuthResultPage(writer, http.StatusOK, state, true, "Authorization completed. You may close this window.")
}

func (s *Server) mcpOAuthCancel(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		State string `json:"state"`
	}
	if err := httpjson.Decode(request, &body, 4096); err != nil || !validPortalOAuthToken(body.State, 32) {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid OAuth cancellation"})
		return
	}
	session := request.Context().Value(sessionContextKey).(store.Session)
	binding, err := s.store.ConsumeOAuthState(request.Context(), body.State, session.TokenHash, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(writer, http.StatusOK, map[string]bool{"success": true})
		return
	}
	if err != nil || binding.TenantID != session.User.TenantID {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "OAuth state did not match this session"})
		return
	}
	var status runtimeIdentityStatus
	if err := s.callRuntimeControl(request.Context(), session.User, http.MethodGet, "/internal/status", nil, &status); err != nil || status.StartedAt.UTC().Format(time.RFC3339Nano) != binding.RuntimeStartedAt {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.cancel", "instance_failed", nil)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "OAuth state was invalidated, but the tenant runtime could not be notified"})
		return
	}
	if err := s.callRuntimeControl(request.Context(), session.User, http.MethodPost, "/internal/oauth/cancel", map[string]string{"flow_id": binding.FlowID, "server_url": binding.Target}, nil); err != nil {
		s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.cancel", "instance_failed", nil)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "OAuth state was invalidated, but the tenant runtime could not be notified"})
		return
	}
	s.auditOAuthBestEffort(request, session.User, "portal.mcp_oauth.cancel", "success", nil)
	writeJSON(writer, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) mcpOAuthPopup(writer http.ResponseWriter, request *http.Request) {
	channel := request.URL.Query().Get("channel")
	if !validPortalOAuthToken(channel, 16) {
		http.Error(writer, "Invalid OAuth popup channel", http.StatusBadRequest)
		return
	}
	nonce, err := auth.RandomToken(18)
	if err != nil {
		http.Error(writer, "OAuth popup could not be rendered", http.StatusInternalServerError)
		return
	}
	channelJSON, _ := json.Marshal(channel)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Security-Policy", oauthPageCSP(nonce))
	_, _ = fmt.Fprintf(writer, `<!doctype html><html><head><meta charset="utf-8"><title>WorkAgent2 OAuth</title></head><body><p id="status">Preparing secure authorization…</p><script nonce="%s">(function(){"use strict";var id=%s;var c=new BroadcastChannel("aionui-mcp-oauth-launch:"+id);var timer=setInterval(function(){c.postMessage({type:"ready"})},500);c.postMessage({type:"ready"});c.onmessage=function(e){var v=e.data||{};if(v.type==="close"){clearInterval(timer);c.close();window.close()}else if(v.type==="authorize"&&typeof v.authorization_url==="string"&&typeof v.state==="string"){try{var u=new URL(v.authorization_url);if(u.protocol!=="https:"||u.searchParams.get("state")!==v.state)throw 0;clearInterval(timer);c.close();location.replace(u.href)}catch(_){document.getElementById("status").textContent="Authorization URL rejected."}}}})();</script></body></html>`, nonce, channelJSON)
}

func (s *Server) mcpOAuthBridge(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = io.WriteString(writer, portalOAuthBridgeScript)
}

func (s *Server) writeOAuthResultPage(writer http.ResponseWriter, status int, state string, success bool, message string) {
	nonce, err := auth.RandomToken(18)
	if err != nil {
		http.Error(writer, "OAuth result could not be rendered", http.StatusInternalServerError)
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "aionui-portal-mcp-oauth-result", "state": state, "success": success, "error": func() string {
		if success {
			return ""
		}
		return message
	}()})
	messageJSON, _ := json.Marshal(message)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Security-Policy", oauthPageCSP(nonce))
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, `<!doctype html><html><head><meta charset="utf-8"><title>WorkAgent2 OAuth</title></head><body><p id="status"></p><script nonce="%s">(function(){"use strict";history.replaceState(null,"","/api/mcp/oauth/callback");var p=%s;document.getElementById("status").textContent=%s;if(p.state&&("BroadcastChannel" in window)){var c=new BroadcastChannel("aionui-mcp-oauth-result:"+p.state);c.postMessage(p);setTimeout(function(){c.postMessage(p);c.close();window.close()},200)}})();</script></body></html>`, nonce, payload, messageJSON)
}

func (s *Server) auditOAuthBestEffort(request *http.Request, user store.User, action, outcome string, details map[string]any) {
	remoteIP, _ := request.Context().Value(remoteIPContextKey).(string)
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: s.now(), Action: action, Outcome: outcome, Username: user.Username, TenantID: user.TenantID, RemoteIP: remoteIP, Details: details}); err != nil {
		s.logger.Printf("OAuth audit failed action=%s tenant=%s", action, user.TenantID)
	}
}

func normalizeMCPServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("MCP server URL is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("MCP server URL must be HTTPS without credentials, query, or fragment")
	}
	return parsed.String(), nil
}

func validAuthorizationResult(raw, state string) bool {
	if raw == "" || len(raw) > 16*1024 {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && parsed.Query().Get("state") == state
}

func validPortalOAuthToken(value string, size int) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	defer clear(decoded)
	return err == nil && len(decoded) == size
}

func oauthPageCSP(nonce string) string {
	return fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nonce, nonce)
}

const portalOAuthBridgeScript = `(function () {
  "use strict";
  if (window.__workagentOAuthBridge) return;
  window.__workagentOAuthBridge = true;
  var nativeFetch = window.fetch.bind(window);
  var brandLogoURL = "/brand/logo?v=workagent-v1";
  var brandIconURL = "/brand/app-icon?v=workagent-v1";
  var rendererLogoPath = /^\/assets\/app-[A-Za-z0-9_-]{8,}\.png$/;
  var legacyBrandName = "WorkAgent" + " AI";

  function brandedText(value) {
    return typeof value === "string" ? value.split(legacyBrandName).join("WorkAgent2") : value;
  }

  function replaceRendererBrandText(root) {
    if (!root) return;
    if (root.nodeType === 3) {
      if (root.parentElement && /^(SCRIPT|STYLE|TEXTAREA)$/.test(root.parentElement.tagName)) return;
      var text = brandedText(root.nodeValue);
      if (text !== root.nodeValue) root.nodeValue = text;
      return;
    }
    if (root.nodeType !== 1) return;
    var elements = [root];
    if (root.querySelectorAll) elements = elements.concat(Array.prototype.slice.call(root.querySelectorAll("*")));
    elements.forEach(function (element) {
      ["title", "aria-label", "alt", "placeholder", "content"].forEach(function (name) {
        if (!element.hasAttribute || !element.hasAttribute(name)) return;
        var value = element.getAttribute(name);
        var branded = brandedText(value);
        if (branded !== value) element.setAttribute(name, branded);
      });
    });
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var node;
    while ((node = walker.nextNode())) replaceRendererBrandText(node);
  }

  function replaceRendererBranding(root) {
    replaceRendererBrandText(root);
    if (!root || root.nodeType !== 1) return;
    var images = [];
    var icons = [];
    if (root.matches && root.matches("img")) images.push(root);
    if (root.matches && root.matches('link[rel~="icon"], link[rel="apple-touch-icon"]')) icons.push(root);
    if (root.querySelectorAll) images = images.concat(Array.prototype.slice.call(root.querySelectorAll("img")));
    images.forEach(function (image) {
      try {
        var source = image.getAttribute("src") || "";
        if (!rendererLogoPath.test(new URL(source, location.href).pathname)) return;
        if (source !== brandLogoURL) image.setAttribute("src", brandLogoURL);
        if (!image.alt || image.alt === "WorkAgent" + " AI") image.alt = "WorkAgent2";
        image.style.setProperty("object-fit", "contain", "important");
        image.style.setProperty("object-position", "center center", "important");
      } catch (_) {}
    });
    if (root.querySelectorAll) icons = icons.concat(Array.prototype.slice.call(root.querySelectorAll('link[rel~="icon"], link[rel="apple-touch-icon"]')));
    icons.forEach(function (link) {
      if (link.getAttribute("href") !== brandIconURL) link.setAttribute("href", brandIconURL);
    });
  }

  function installBrandBridge() {
    replaceRendererBranding(document.documentElement);
    new MutationObserver(function (records) {
      records.forEach(function (record) {
        if (record.type === "characterData") replaceRendererBranding(record.target);
        record.addedNodes.forEach(replaceRendererBranding);
      });
    }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  }

  if (document.documentElement) installBrandBridge();
  else document.addEventListener("DOMContentLoaded", installBrandBridge, { once: true });

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
