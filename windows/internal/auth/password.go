package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16
	argonKeyLength   = 32
)

func ValidatePortalPassword(password []byte) error {
	if !utf8.Valid(password) {
		return errors.New("password must be valid UTF-8")
	}
	runes := utf8.RuneCount(password)
	if runes < 12 {
		return errors.New("password must contain at least 12 characters")
	}
	if len(password) > 256 {
		return errors.New("password must not exceed 256 UTF-8 bytes")
	}
	return nil
}

func ValidatePortalUsername(username string) error {
	if len(username) < 1 || len(username) > 64 {
		return errors.New("Portal username must be between 1 and 64 ASCII characters")
	}
	for index, character := range username {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return errors.New("Portal username must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen")
	}
	return nil
}

func HashPassword(password []byte) (string, error) {
	if err := ValidatePortalPassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(password, salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	defer zero(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded string, password []byte) bool {
	parameters, ok := decodePasswordHash(encoded)
	if !ok {
		return false
	}
	defer zero(parameters.expected)
	actual := argon2.IDKey(password, parameters.salt, parameters.iterations, parameters.memory, parameters.parallelism, uint32(len(parameters.expected)))
	defer zero(actual)
	return subtle.ConstantTimeCompare(actual, parameters.expected) == 1
}

func ValidatePasswordHash(encoded string) error {
	parameters, ok := decodePasswordHash(encoded)
	if !ok {
		return errors.New("invalid Argon2id password hash")
	}
	zero(parameters.expected)
	return nil
}

type passwordHashParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	expected    []byte
}

func decodePasswordHash(encoded string) (passwordHashParameters, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return passwordHashParameters{}, false
	}
	var memory uint64
	var iterations uint64
	var parallelism uint64
	for _, field := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			return passwordHashParameters{}, false
		}
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return passwordHashParameters{}, false
		}
		switch kv[0] {
		case "m":
			memory = value
		case "t":
			iterations = value
		case "p":
			parallelism = value
		default:
			return passwordHashParameters{}, false
		}
	}
	if memory != argonMemory || iterations != argonIterations || parallelism != argonParallelism {
		return passwordHashParameters{}, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return passwordHashParameters{}, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != argonKeyLength {
		return passwordHashParameters{}, false
	}
	return passwordHashParameters{memory: uint32(memory), iterations: uint32(iterations), parallelism: uint8(parallelism), salt: salt, expected: expected}, true
}

func RandomToken(bytes int) (string, error) {
	if bytes < 16 || bytes > 128 {
		return "", errors.New("token entropy size must be between 16 and 128 bytes")
	}
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	defer zero(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func Zero(b []byte) { zero(b) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
