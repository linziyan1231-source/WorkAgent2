package winmigration

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

var managedCodexKeys = map[string]bool{
	"openai_base_url": true, "model_reasoning_effort": true, "model": true,
	"cli_auth_credentials_store": true, "model_catalog_json": true,
}

func sanitizeCodexConfig(payload []byte) ([]byte, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var lines []string
	inTable := false
	removed := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
		}
		if !inTable {
			if strings.HasPrefix(trimmed, "# Managed Codex model catalog:") || strings.HasPrefix(trimmed, "# Initial CLIProxyAPI settings managed by WorkAgent2.") {
				removed++
				continue
			}
			if key, value, ok := tomlAssignment(trimmed); ok && managedCodexKeys[key] {
				if strings.HasPrefix(value, `"""`) || strings.HasPrefix(value, `'''`) {
					return nil, 0, errors.New("managed Codex setting uses an unsupported multiline value")
				}
				removed++
				continue
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	return normalizedText(lines), removed, nil
}

func sanitizeKimiConfig(payload []byte) ([]byte, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var lines []string
	removed := 0
	skipTable := false
	inTable := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
			skipTable = managedKimiTable(trimmed)
			if skipTable {
				removed++
				continue
			}
		}
		if skipTable {
			removed++
			continue
		}
		if strings.HasPrefix(trimmed, "# BEGIN WORKAGENT2 MANAGED KIMI") || strings.HasPrefix(trimmed, "# END WORKAGENT2 MANAGED KIMI") || strings.HasPrefix(trimmed, "# BEGIN WorkAgent2 MANAGED KIMI") || strings.HasPrefix(trimmed, "# END WorkAgent2 MANAGED KIMI") {
			removed++
			continue
		}
		if !inTable {
			if key, value, ok := tomlAssignment(trimmed); ok && (key == "default_model" || key == "default_thinking" || key == "default_yolo") {
				if strings.HasPrefix(value, `"""`) || strings.HasPrefix(value, `'''`) {
					return nil, 0, errors.New("managed Kimi setting uses an unsupported multiline value")
				}
				removed++
				continue
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	return normalizedText(lines), removed, nil
}

func managedKimiTable(header string) bool {
	lower := strings.ToLower(header)
	if lower == `[providers."managed:kimi-code"]` || strings.HasPrefix(lower, `[providers."managed:kimi-code".`) {
		return true
	}
	for _, prefix := range []string{`[models."kimi-code/`, `[models."workagent-managed/`, `[models."workagent-managed/`} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func tomlAssignment(trimmed string) (key, value string, ok bool) {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key = strings.Trim(strings.TrimSpace(parts[0]), `"'`)
	return key, strings.TrimSpace(parts[1]), key != ""
}

func normalizedText(lines []string) []byte {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
