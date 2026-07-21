package portal

import (
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) chatGPTBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false})
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, chatGPTBridgeScript)
}

func (s *Server) chatGPTHome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false})
		return
	}
	http.Redirect(w, r, "/#/chat", http.StatusFound)
}

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

const chatGPTBridgeScript = `(() => {
  'use strict';
  if (window.__workagentChatGPTBridgeInstalled) return;
  window.__workagentChatGPTBridgeInstalled = true;

  const addReturnButton = () => {
    if (!document.body || document.getElementById('workagent-platform-return')) return;
    const link = document.createElement('a');
    link.id = 'workagent-platform-return';
    link.href = '/chatgpt/portal-home';
    link.setAttribute('aria-label', '主界面');
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.id = 'workagent-platform-return-icon';
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('width', '17');
    icon.setAttribute('height', '17');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '1.8');
    icon.setAttribute('stroke-linecap', 'round');
    icon.setAttribute('stroke-linejoin', 'round');
    icon.setAttribute('aria-hidden', 'true');
    const roof = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    roof.setAttribute('d', 'M3.5 10.5 12 3.5l8.5 7');
    const home = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    home.setAttribute('d', 'M5.5 9.5v10.75h13V9.5M9.5 20.25v-6h5v6');
    icon.append(roof, home);
    const label = document.createElement('span');
    label.textContent = '主界面';
    link.append(icon, label);
    Object.assign(link.style, {
      position: 'fixed', top: '12px', right: '16px', zIndex: '2147483000',
      display: 'inline-flex', alignItems: 'center', gap: '7px', height: '36px', padding: '0 14px',
      border: '1px solid rgba(127,127,127,.28)', borderRadius: '10px',
      background: 'var(--main-surface-primary, rgba(255,255,255,.94))', color: 'var(--text-primary, #111827)',
      boxShadow: '0 4px 16px rgba(0,0,0,.10)', textDecoration: 'none',
      font: '500 13px/1 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    });
    document.body.appendChild(link);
  };

  const proStatusText = '目前处于降智状态，暂不可用，请使用5.6 balanced Extra high。';
  const findSelectedProButton = () => {
    if (!document.body) return;
    for (const button of document.querySelectorAll('button')) {
      if (!(button instanceof HTMLElement) || button.textContent.trim() !== 'Pro') continue;
      const rect = button.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0 || rect.left < window.innerWidth * 0.35 || rect.width > 160 || rect.height > 64) continue;
      const semanticHint = [
        button.getAttribute('aria-haspopup'), button.getAttribute('aria-expanded'),
        button.getAttribute('aria-label'), button.getAttribute('data-testid')
      ].filter(Boolean).join(' ').toLowerCase();
      const hasSelectorSemantics = semanticHint.includes('menu') || semanticHint.includes('listbox') ||
        semanticHint.includes('thinking') || semanticHint.includes('reason') || semanticHint.includes('intelligence') ||
        Array.from(button.querySelectorAll('use')).some((use) => {
          const href = use.getAttribute('href') || use.getAttribute('xlink:href') || '';
          return href.endsWith('#ba3792');
        });
      if (hasSelectorSemantics) return button;
    }
    return undefined;
  };

  const syncProStatusNote = () => {
    if (!document.body) return;
    const selectedButton = findSelectedProButton();
    const notes = Array.from(document.querySelectorAll('[data-workagent-pro-status-note="true"]'));
    if (!selectedButton) {
      for (const note of notes) note.remove();
      return;
    }
    let host = selectedButton.parentElement;
    for (let depth = 0; depth < 5 && host && host.parentElement; depth += 1) {
      const parent = host.parentElement;
      const parentRect = parent.getBoundingClientRect();
      if (parent.textContent.trim() !== 'Pro' || parentRect.width > 220 || parentRect.height > 80) break;
      host = parent;
    }
    if (!host) return;
    if (notes.length === 1 && notes[0].parentElement === host) return;
    for (const note of notes) note.remove();
    const note = document.createElement('span');
    note.setAttribute('data-workagent-pro-status-note', 'true');
    note.textContent = proStatusText;
    Object.assign(note.style, {
      display: 'inline-block', maxWidth: '340px', marginRight: '8px', color: '#d97706',
      font: '600 12px/1.35 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      whiteSpace: 'normal', textAlign: 'right', pointerEvents: 'none'
    });
    host.prepend(note);
  };

  let modalOpen = false;
  const acknowledge = async (id) => {
    try {
      await fetch('/api/portal/me/chatgpt/pro-events', {
        method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ids: [id] })
      });
    } catch {}
  };
  const showFallback = (event) => {
    if (modalOpen || !document.body) return;
    modalOpen = true;
    const overlay = document.createElement('div');
    overlay.id = 'workagent-pro-fallback-modal';
    Object.assign(overlay.style, {
      position: 'fixed', inset: '0', zIndex: '2147483646', display: 'grid', placeItems: 'center',
      padding: '24px', background: 'rgba(0,0,0,.48)', fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    });
    const dialog = document.createElement('div');
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    Object.assign(dialog.style, {
      width: 'min(560px, calc(100vw - 48px))', borderRadius: '16px', padding: '24px',
      background: 'var(--main-surface-primary, #fff)', color: 'var(--text-primary, #111827)',
      boxShadow: '0 24px 80px rgba(0,0,0,.28)', fontSize: '15px', lineHeight: '1.75'
    });
    const title = document.createElement('div');
    title.textContent = '模型降智提醒';
    Object.assign(title.style, { fontSize: '18px', fontWeight: '700', marginBottom: '10px' });
    const message = document.createElement('div');
    message.append('遇到模型降智，请在新的窗口重新发送相关文件和指令并');
    const strong = document.createElement('strong');
    strong.textContent = '【将思考程度（Intelligence）切换至“超高”（“Extra High”）】';
    message.append(strong, '。新的思考程度可能会造成内容生成质量下降。');
    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', justifyContent: 'flex-end', marginTop: '18px' });
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '知道了';
    Object.assign(close.style, {
      height: '36px', padding: '0 16px', border: '0', borderRadius: '9px', cursor: 'pointer',
      background: '#111827', color: '#fff', font: '600 14px system-ui, sans-serif'
    });
    close.addEventListener('click', () => {
      overlay.remove(); modalOpen = false; void acknowledge(event.id);
    }, { once: true });
    actions.appendChild(close);
    dialog.append(title, message, actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    close.focus();
  };

  const pollProEvents = async () => {
    if (modalOpen || document.visibilityState === 'hidden') return;
    try {
      const response = await fetch('/api/portal/me/chatgpt/pro-events', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) return;
      const payload = await response.json();
      const event = payload && payload.data && Array.isArray(payload.data.events) ? payload.data.events[0] : null;
      if (event && Number.isInteger(event.id)) showFallback(event);
    } catch {}
  };

  const notificationSeenKey = 'workagent-portal-notification-seen-v1';
  const readSeenNotifications = () => {
    try {
      const value = JSON.parse(localStorage.getItem(notificationSeenKey) || '[]');
      return new Set(Array.isArray(value) ? value.filter((id) => typeof id === 'string').slice(-200) : []);
    } catch { return new Set(); }
  };
  const seenNotifications = readSeenNotifications();
  const rememberNotification = (id) => {
    seenNotifications.add(id);
    try { localStorage.setItem(notificationSeenKey, JSON.stringify(Array.from(seenNotifications).slice(-200))); } catch {}
  };
  const showNotification = (notification) => {
    if (modalOpen || !document.body || !notification || typeof notification.id !== 'string') return;
    modalOpen = true;
    const overlay = document.createElement('div');
    overlay.id = 'workagent-portal-notification-modal';
    Object.assign(overlay.style, {
      position: 'fixed', inset: '0', zIndex: '2147483646', display: 'grid', placeItems: 'center',
      padding: '24px', background: 'rgba(0,0,0,.48)', fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    });
    const dialog = document.createElement('div');
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    Object.assign(dialog.style, {
      width: 'min(560px, calc(100vw - 48px))', borderRadius: '16px', padding: '24px',
      background: 'var(--main-surface-primary, #fff)', color: 'var(--text-primary, #111827)',
      boxShadow: '0 24px 80px rgba(0,0,0,.28)', fontSize: '15px', lineHeight: '1.75'
    });
    const title = document.createElement('div');
    title.textContent = typeof notification.title === 'string' && notification.title.trim() ? notification.title : '通知';
    Object.assign(title.style, { fontSize: '18px', fontWeight: '700', marginBottom: '10px' });
    const message = document.createElement('div');
    message.textContent = notification.message;
    Object.assign(message.style, { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' });
    const actions = document.createElement('div');
    Object.assign(actions.style, { display: 'flex', justifyContent: 'flex-end', marginTop: '18px' });
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '知道了';
    Object.assign(close.style, {
      height: '36px', padding: '0 16px', border: '0', borderRadius: '9px', cursor: 'pointer',
      background: '#111827', color: '#fff', font: '600 14px system-ui, sans-serif'
    });
    close.addEventListener('click', () => {
      rememberNotification(notification.id);
      overlay.remove();
      modalOpen = false;
      window.setTimeout(pollNotifications, 0);
    }, { once: true });
    actions.appendChild(close);
    dialog.append(title, message, actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    close.focus();
  };

  let notificationRequestInFlight = false;
  const pollNotifications = async () => {
    if (notificationRequestInFlight || modalOpen || document.visibilityState === 'hidden') return;
    notificationRequestInFlight = true;
    try {
      const response = await fetch('/api/portal/me/notifications', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) return;
      const payload = await response.json();
      const notifications = payload && payload.data && Array.isArray(payload.data.notifications) ? payload.data.notifications : [];
      const next = notifications.find((notification) =>
        notification && typeof notification.id === 'string' && typeof notification.message === 'string' &&
        notification.message.trim() && !seenNotifications.has(notification.id)
      );
      if (next) showNotification(next);
    } catch {
    } finally {
      notificationRequestInFlight = false;
    }
  };

  const keepReturnButtonMounted = () => {
    addReturnButton();
    syncProStatusNote();
    const root = document.documentElement;
    if (!root) return;
    let observerFrame = 0;
    new MutationObserver(() => {
      if (observerFrame) return;
      observerFrame = window.requestAnimationFrame(() => {
        observerFrame = 0;
        addReturnButton();
        syncProStatusNote();
      });
    }).observe(root, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', keepReturnButtonMounted, { once: true });
  else keepReturnButtonMounted();
  const pollNotificationsWhenActive = () => {
    if (document.visibilityState === 'visible') void pollNotifications();
  };
  document.addEventListener('visibilitychange', pollNotificationsWhenActive);
  window.addEventListener('focus', pollNotificationsWhenActive);
  window.addEventListener('online', pollNotificationsWhenActive);
  window.setInterval(pollProEvents, 2500);
  window.setInterval(pollNotifications, 60000);
  void pollProEvents();
  void pollNotifications();
})();
`
