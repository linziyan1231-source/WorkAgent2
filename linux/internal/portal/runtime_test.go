package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProjectControlErrorsMatchWindowsBrowserContract(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		failure   runtimeControlError
		status    int
		code      string
	}{
		{name: "create conflict", operation: "create", failure: runtimeControlError{Status: http.StatusConflict, Code: "PROJECT_EXISTS"}, status: http.StatusConflict, code: "PROJECT_EXISTS"},
		{name: "rename active", operation: "rename", failure: runtimeControlError{Status: http.StatusConflict, Code: "PROJECT_IN_USE"}, status: http.StatusConflict, code: "PROJECT_IN_USE"},
		{name: "rename missing", operation: "rename", failure: runtimeControlError{Status: http.StatusNotFound, Code: "PROJECT_NOT_FOUND"}, status: http.StatusNotFound, code: "PROJECT_NOT_FOUND"},
	}
	server := &Server{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if test.operation == "create" {
				server.writeCreateProjectError(recorder, test.failure)
			} else {
				server.writeRenameProjectError(recorder, test.failure)
			}
			var body struct {
				Success bool   `json:"success"`
				Code    string `json:"code"`
				Error   string `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != test.status || body.Success || body.Code != test.code || body.Error == "" {
				t.Fatalf("unexpected project error: status=%d body=%s err=%v", recorder.Code, recorder.Body.String(), err)
			}
		})
	}
}
