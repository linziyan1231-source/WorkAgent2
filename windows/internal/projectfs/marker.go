package projectfs

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MarkerFileName = ".aionui-project.json"

type Marker struct {
	Version   int    `json:"version"`
	ProjectID string `json:"project_id"`
}

func EnsureMarker(projectDirectory string) (Marker, error) {
	markerPath := filepath.Join(filepath.Clean(projectDirectory), MarkerFileName)
	marker, err := ReadMarker(projectDirectory)
	if err == nil {
		return marker, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Marker{}, err
	}
	random := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return Marker{}, fmt.Errorf("create project id: %w", err)
	}
	marker = Marker{Version: 1, ProjectID: base64.RawURLEncoding.EncodeToString(random)}
	encoded, err := json.Marshal(marker)
	if err != nil {
		return Marker{}, err
	}
	file, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ReadMarker(projectDirectory)
	}
	if err != nil {
		return Marker{}, fmt.Errorf("create project marker: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(markerPath)
		}
	}()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return Marker{}, fmt.Errorf("write project marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		return Marker{}, fmt.Errorf("sync project marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return Marker{}, err
	}
	remove = false
	return marker, nil
}

func WriteMarker(projectDirectory, projectID string) (Marker, error) {
	if len(projectID) != 32 {
		return Marker{}, errors.New("project marker id is invalid")
	}
	if _, err := base64.RawURLEncoding.DecodeString(projectID); err != nil {
		return Marker{}, errors.New("project marker id is invalid")
	}
	markerPath := filepath.Join(filepath.Clean(projectDirectory), MarkerFileName)
	marker := Marker{Version: 1, ProjectID: projectID}
	encoded, err := json.Marshal(marker)
	if err != nil {
		return Marker{}, err
	}
	file, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Marker{}, fmt.Errorf("create project marker: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(markerPath)
		}
	}()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return Marker{}, fmt.Errorf("write project marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		return Marker{}, fmt.Errorf("sync project marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return Marker{}, err
	}
	remove = false
	return marker, nil
}

func ReadMarker(projectDirectory string) (Marker, error) {
	markerPath := filepath.Join(filepath.Clean(projectDirectory), MarkerFileName)
	info, err := os.Lstat(markerPath)
	if err != nil {
		return Marker{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > 1024 {
		return Marker{}, errors.New("project marker must be a bounded regular non-symlink file")
	}
	contents, err := os.ReadFile(markerPath)
	if err != nil {
		return Marker{}, err
	}
	var marker Marker
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || decoder.Decode(&struct{}{}) != io.EOF || marker.Version != 1 || len(marker.ProjectID) != 32 {
		return Marker{}, errors.New("project marker is invalid")
	}
	if _, err := base64.RawURLEncoding.DecodeString(marker.ProjectID); err != nil {
		return Marker{}, errors.New("project marker id is invalid")
	}
	return marker, nil
}
