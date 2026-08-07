package portal

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/store"
)

const (
	maxMarketArchiveBytes = 200 * 1024 * 1024
	maxMarketFileBytes    = 50 * 1024 * 1024
)

func validMarketSkillName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || len([]byte(name)) > 240 || strings.Contains(name, "..") ||
		strings.ContainsAny(name, `/\<>:"|?*`) || strings.HasSuffix(name, ".") {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return false
	}
	return true
}

func (s *Server) skillMarket(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if r.Method == http.MethodGet {
		entries, err := s.store.ListSkillMarketEntries(r.Context())
		if err != nil {
			s.internalError(w, "list skill market", err)
			return
		}
		items := make([]map[string]any, len(entries))
		for index, entry := range entries {
			items[index] = marketSkillPayload(entry, session.User.ID, session.User.Admin)
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "skills": items})
		return
	}
	if r.Method == http.MethodDelete {
		if !s.validBrowserOrigin(r) || len(r.URL.Query()) != 1 || len(r.URL.Query()["id"]) != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "A single market skill id is required"})
			return
		}
		entry, err := s.store.DeleteSkillMarketEntry(r.Context(), r.URL.Query().Get("id"), session.User.ID, session.User.Admin)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrForbidden):
				writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Only the publisher or an administrator can delete this skill"})
			case errors.Is(err, store.ErrNotFound):
				writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Skill market entry was not found"})
			default:
				s.internalError(w, "delete skill market entry", err)
			}
			return
		}
		if err := os.Remove(filepath.Join(s.skillMarketRoot, entry.ArchiveName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.internalError(w, "delete skill market archive", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator accounts cannot publish employee skills"})
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		SkillName string `json:"skill_name"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validMarketSkillName(request.SkillName) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid custom skill name"})
		return
	}
	archive, err := s.fetchCustomSkillPackage(r.Context(), session.User.WindowsSID, request.SkillName)
	if err != nil {
		s.logger.Printf("Skill market packaging failed username=%s skill=%s", session.User.Username, request.SkillName)
		writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "Custom skill could not be packaged"})
		return
	}
	name, description, err := validateMarketSkillArchive(archive)
	if err != nil || name != request.SkillName {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Custom skill package is invalid"})
		return
	}
	archiveID, err := auth.RandomToken(24)
	if err != nil {
		s.internalError(w, "create skill market archive id", err)
		return
	}
	archiveName := archiveID + ".zip"
	archivePath := filepath.Join(s.skillMarketRoot, archiveName)
	if err := writeExclusiveArchive(archivePath, archive); err != nil {
		s.internalError(w, "write skill market archive", err)
		return
	}
	digest := sha256.Sum256(archive)
	entryID, err := auth.RandomToken(18)
	if err != nil {
		_ = os.Remove(archivePath)
		s.internalError(w, "create skill market entry id", err)
		return
	}
	entry, previous, err := s.store.PublishSkillMarketEntry(r.Context(), store.SkillMarketEntry{
		ID: entryID, PublisherUserID: session.User.ID, SkillName: name, Description: description, ArchiveName: archiveName,
		ArchiveSHA256: hex.EncodeToString(digest[:]), ArchiveBytes: int64(len(archive)),
	}, s.now())
	if err != nil {
		_ = os.Remove(archivePath)
		s.internalError(w, "publish skill market entry", err)
		return
	}
	if previous != "" && previous != archiveName {
		_ = os.Remove(filepath.Join(s.skillMarketRoot, previous))
	}
	if err := s.audit(r.Context(), "portal.skill_market.publish", "success", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"entry_id": entry.ID, "skill_name": entry.SkillName, "archive_sha256": entry.ArchiveSHA256}); err != nil {
		s.internalError(w, "audit skill market publish", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "skill": marketSkillPayload(entry, session.User.ID, false)})
}

func (s *Server) downloadMarketSkill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, _, err := s.session(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if len(r.URL.Query()) != 1 || len(r.URL.Query()["id"]) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "A single market skill id is required"})
		return
	}
	entry, err := s.store.SkillMarketEntryByID(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Market skill was not found"})
		return
	}
	archivePath := filepath.Join(s.skillMarketRoot, entry.ArchiveName)
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != entry.ArchiveBytes {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Market skill archive is unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, entry.SkillName))
	w.Header().Set("X-Content-SHA256", entry.ArchiveSHA256)
	http.ServeFile(w, r, archivePath)
}

func (s *Server) installMarketSkill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if session.User.Admin || !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Employee browser session is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var request struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid market skill install request"})
		return
	}
	entry, err := s.store.SkillMarketEntryByID(r.Context(), request.ID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Market skill was not found"})
		return
	}
	archivePath := filepath.Join(s.skillMarketRoot, entry.ArchiveName)
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != entry.ArchiveBytes {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Market skill archive is unavailable"})
		return
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil || int64(len(archive)) != entry.ArchiveBytes {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Market skill archive is unavailable"})
		return
	}
	digest := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), entry.ArchiveSHA256) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Market skill archive integrity check failed"})
		return
	}
	finish, err := s.instances.BeginRequest(session.User.WindowsSID, false)
	if err != nil {
		s.internalError(w, "begin market skill install", err)
		return
	}
	defer finish()
	if _, err := s.instances.Ensure(r.Context(), session.User.WindowsSID); err != nil {
		s.internalError(w, "ensure employee runtime for market skill install", err)
		return
	}
	route, err := s.instances.Route(r.Context(), session.User.WindowsSID)
	if err != nil {
		s.internalError(w, "route market skill install", err)
		return
	}
	target := fmt.Sprintf("http://127.0.0.1:%d/api/skills/market-install", route.Status.WebPort)
	downstream, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(archive))
	if err != nil {
		s.internalError(w, "create market skill install request", err)
		return
	}
	downstream.Header.Set("Content-Type", "application/zip")
	downstream.Header.Set("Cookie", route.Auth.CookieHeader)
	downstream.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", route.Status.AionCorePort))
	if route.Auth.CSRFToken != "" {
		downstream.Header.Set("X-CSRF-Token", route.Auth.CSRFToken)
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(downstream)
	if err != nil {
		s.internalError(w, "install market skill", err)
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		s.internalError(w, "read market skill install response", err)
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "Market skill could not be installed"})
		return
	}
	if err := s.audit(r.Context(), "portal.skill_market.install", "success", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"entry_id": entry.ID, "skill_name": entry.SkillName, "archive_sha256": entry.ArchiveSHA256}); err != nil {
		s.internalError(w, "audit market skill install", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseBody)
}

func (s *Server) fetchCustomSkillPackage(ctx context.Context, sid, skillName string) ([]byte, error) {
	finish, err := s.instances.BeginRequest(sid, false)
	if err != nil {
		return nil, err
	}
	defer finish()
	if _, err := s.instances.Ensure(ctx, sid); err != nil {
		return nil, err
	}
	route, err := s.instances.Route(ctx, sid)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"skill_name": skillName})
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("http://127.0.0.1:%d/api/skills/market-package", route.Status.WebPort)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cookie", route.Auth.CookieHeader)
	request.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", route.Status.AionCorePort))
	if route.Auth.CSRFToken != "" {
		request.Header.Set("X-CSRF-Token", route.Auth.CSRFToken)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/zip") {
		return nil, fmt.Errorf("skill package endpoint returned HTTP %d", response.StatusCode)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxMarketArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(archive) == 0 || len(archive) > maxMarketArchiveBytes {
		return nil, errors.New("skill package exceeded archive size limit")
	}
	return archive, nil
}

func validateMarketSkillArchive(archive []byte) (string, string, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) == 0 || len(reader.File) > 4096 {
		return "", "", errors.New("invalid market skill zip")
	}
	var root, manifest string
	var total uint64
	for _, file := range reader.File {
		name := file.Name
		clean := path.Clean(name)
		if name == "" || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
			return "", "", errors.New("unsafe market skill path")
		}
		parts := strings.Split(clean, "/")
		if len(parts) < 2 || !validMarketSkillName(parts[0]) {
			return "", "", errors.New("market skill archive must have one root directory")
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return "", "", errors.New("market skill archive has multiple roots")
		}
		if file.Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 > maxMarketFileBytes {
			return "", "", errors.New("market skill archive contains a link or oversized file")
		}
		total += file.UncompressedSize64
		if total > maxMarketArchiveBytes {
			return "", "", errors.New("market skill archive exceeds total size limit")
		}
		if clean == root+"/SKILL.md" {
			if manifest != "" {
				return "", "", errors.New("market skill archive contains multiple manifests")
			}
			opened, err := file.Open()
			if err != nil {
				return "", "", err
			}
			contents, readErr := io.ReadAll(io.LimitReader(opened, maxMarketFileBytes+1))
			closeErr := opened.Close()
			if readErr != nil || closeErr != nil || len(contents) > maxMarketFileBytes {
				return "", "", errors.New("market skill manifest could not be read")
			}
			manifest = string(contents)
		}
	}
	name, description, err := parseSkillFrontmatter(manifest)
	if err != nil || name != root {
		return "", "", errors.New("market skill manifest does not match archive root")
	}
	return name, description, nil
}

func parseSkillFrontmatter(contents string) (string, string, error) {
	lines := strings.Split(strings.ReplaceAll(contents, "\r\n", "\n"), "\n")
	if len(lines) < 4 || strings.TrimSpace(lines[0]) != "---" {
		return "", "", errors.New("skill frontmatter is missing")
	}
	var name, description string
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `'"`)
		switch strings.TrimSpace(key) {
		case "name":
			name = value
		case "description":
			description = value
		}
	}
	if !validMarketSkillName(name) || description == "" || len(description) > 4096 {
		return "", "", errors.New("invalid skill metadata")
	}
	return name, description, nil
}

func writeExclusiveArchive(destination string, contents []byte) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func marketSkillPayload(entry store.SkillMarketEntry, viewerID int64, admin bool) map[string]any {
	return map[string]any{
		"id": entry.ID, "name": entry.SkillName, "description": entry.Description,
		"publisher":  map[string]any{"username": entry.PublisherUsername, "display_name": entry.PublisherDisplayName},
		"updated_at": entry.UpdatedAt.UTC().Format(time.RFC3339), "archive_bytes": entry.ArchiveBytes,
		"can_delete": admin || entry.PublisherUserID == viewerID,
	}
}
