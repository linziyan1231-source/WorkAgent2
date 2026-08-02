package portal

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/provisionipc"
)

type provisionJob struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Status       string `json:"status"`
	Percent      int    `json:"percent"`
	Step         string `json:"step"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	CreatedBy    string `json:"-"`
	PeerIP       string `json:"-"`
}

type provisionJobStore struct {
	mu    sync.Mutex
	items map[string]provisionJob
}

func (s *Server) startProvisionJob(w http.ResponseWriter, username string, password []byte, actor, sourceIP string) {
	id, err := auth.RandomToken(18)
	if err != nil {
		s.internalError(w, "create provision job", err)
		return
	}
	job := provisionJob{ID: id, Username: username, Status: "running", Percent: 5, Step: "queued", CreatedBy: actor, PeerIP: sourceIP}
	s.provisionJobs.mu.Lock()
	for _, existing := range s.provisionJobs.items {
		if existing.Status == "running" && strings.EqualFold(existing.Username, username) {
			s.provisionJobs.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "Account creation is already in progress"})
			return
		}
	}
	s.provisionJobs.items[id] = job
	s.provisionJobs.mu.Unlock()

	secret := append([]byte(nil), password...)
	go s.runProvisionJob(job, secret)
	writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "job": job})
}

func (s *Server) runProvisionJob(job provisionJob, password []byte) {
	defer auth.Zero(password)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	response, err := s.provision(ctx, provisionipc.Request{
		Command:        "add-user",
		Username:       job.Username,
		PortalPassword: password,
		Nonce:          job.ID,
	}, func(progress provisionipc.Progress) {
		s.updateProvisionJob(job.ID, progress.Percent, progress.Step)
	})
	if err != nil {
		code := "PROVISION_FAILED"
		var remoteError *provisionipc.RemoteError
		if errors.As(err, &remoteError) && remoteError.Code != "" {
			code = remoteError.Code
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = "PROVISION_TIMEOUT"
		}
		s.failProvisionJob(job.ID, code, err.Error())
		return
	}
	if response.User == nil {
		s.failProvisionJob(job.ID, "INVALID_PROVISION_RESPONSE", "Provision service returned no user")
		return
	}
	created, err := s.store.UserByUsername(ctx, response.User.Username)
	if err != nil {
		s.failProvisionJob(job.ID, "PROVISION_FAILED", err.Error())
		return
	}
	if err := s.audit(ctx, "portal.admin.user.add", "success", created.Username, created.WindowsSID, job.PeerIP, map[string]any{"actor": job.CreatedBy}); err != nil {
		s.failProvisionJob(job.ID, "PROVISION_FAILED", err.Error())
		return
	}
	s.provisionJobs.mu.Lock()
	current := s.provisionJobs.items[job.ID]
	current.Status, current.Percent, current.Step = "succeeded", 100, "completed"
	s.provisionJobs.items[job.ID] = current
	s.provisionJobs.mu.Unlock()
}

func (s *Server) updateProvisionJob(id string, percent int, step string) {
	s.provisionJobs.mu.Lock()
	job := s.provisionJobs.items[id]
	if job.Status == "running" {
		job.Percent, job.Step = percent, step
		s.provisionJobs.items[id] = job
	}
	s.provisionJobs.mu.Unlock()
}

func (s *Server) failProvisionJob(id, code, message string) {
	s.provisionJobs.mu.Lock()
	job := s.provisionJobs.items[id]
	job.Status, job.Step, job.ErrorCode, job.ErrorMessage = "failed", "failed", code, message
	s.provisionJobs.items[id] = job
	s.provisionJobs.mu.Unlock()
}

func (s *Server) adminUserJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	ids, valid := r.URL.Query()["id"]
	if !valid || len(r.URL.Query()) != 1 || len(ids) != 1 || ids[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Exactly one provision job ID is required"})
		return
	}
	s.provisionJobs.mu.Lock()
	job, exists := s.provisionJobs.items[ids[0]]
	s.provisionJobs.mu.Unlock()
	if !exists || job.CreatedBy != session.User.Username {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Provision job was not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "job": job})
}
