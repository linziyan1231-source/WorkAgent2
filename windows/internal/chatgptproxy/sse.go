package chatgptproxy

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	OutcomeConfirmedPro      = "confirmed_pro"
	OutcomeConfirmedFallback = "confirmed_fallback"
	OutcomeUnknown           = "unknown"
)

type StreamSummary struct {
	Completed    bool
	DoneEvents   int
	EventTypes   map[string]int
	JSONEvents   int
	ParseFailed  bool
	ServedModels []string
}

type SSEInspector struct {
	buffer  string
	summary StreamSummary
	models  map[string]struct{}
}

func NewSSEInspector() *SSEInspector {
	return &SSEInspector{
		summary: StreamSummary{EventTypes: make(map[string]int)},
		models:  make(map[string]struct{}),
	}
}

func (i *SSEInspector) Write(chunk []byte) {
	i.buffer += string(chunk)
	for {
		index := strings.IndexByte(i.buffer, '\n')
		if index < 0 {
			return
		}
		line := strings.TrimSuffix(i.buffer[:index], "\r")
		i.buffer = i.buffer[index+1:]
		i.consumeLine(line)
	}
}

func (i *SSEInspector) Finish() StreamSummary {
	if strings.TrimSpace(i.buffer) != "" {
		i.consumeLine(strings.TrimSuffix(i.buffer, "\r"))
	}
	i.buffer = ""
	i.summary.ServedModels = make([]string, 0, len(i.models))
	for model := range i.models {
		i.summary.ServedModels = append(i.summary.ServedModels, model)
	}
	sort.Strings(i.summary.ServedModels)
	return i.summary
}

func (i *SSEInspector) consumeLine(line string) {
	if !strings.HasPrefix(line, "data:") {
		return
	}
	data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
	if data == "[DONE]" {
		i.summary.DoneEvents++
		i.summary.Completed = true
		return
	}
	if data == "" {
		return
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		i.summary.ParseFailed = true
		return
	}
	i.summary.JSONEvents++
	eventType, _ := event["type"].(string)
	if eventType != "" {
		i.summary.EventTypes[eventType]++
	}
	if eventType == "message_stream_complete" {
		i.summary.Completed = true
	}
	if eventType == "server_ste_metadata" {
		collectModels(event, i.models)
	}
	if containsStringValue(event, "status", "finished_successfully") {
		i.summary.Completed = true
	}
}

func (i *SSEInspector) Outcome(requestedModel string, configuredProModels []string) (string, StreamSummary) {
	summary := i.Finish()
	if summary.ParseFailed || !summary.Completed || len(summary.ServedModels) == 0 {
		return OutcomeUnknown, summary
	}
	hasRequested := false
	for _, model := range summary.ServedModels {
		if !IsProModel(model, configuredProModels) {
			return OutcomeConfirmedFallback, summary
		}
		if strings.EqualFold(model, requestedModel) {
			hasRequested = true
		}
	}
	if hasRequested {
		return OutcomeConfirmedPro, summary
	}
	return OutcomeUnknown, summary
}

func collectModels(value any, models map[string]struct{}) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectModels(item, models)
		}
	case map[string]any:
		for key, item := range typed {
			if (key == "model" || key == "model_slug") && item != nil {
				if model, ok := item.(string); ok && strings.TrimSpace(model) != "" {
					models[strings.TrimSpace(model)] = struct{}{}
				}
			}
			collectModels(item, models)
		}
	}
}

func containsStringValue(value any, key, expected string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if containsStringValue(item, key, expected) {
				return true
			}
		}
	case map[string]any:
		for itemKey, item := range typed {
			if itemKey == key {
				if text, ok := item.(string); ok && text == expected {
					return true
				}
			}
			if containsStringValue(item, key, expected) {
				return true
			}
		}
	}
	return false
}
