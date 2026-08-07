package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrForbidden = errors.New("forbidden")

func ValidateDisplayName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || utf8.RuneCountInString(value) > 64 {
		return "", errors.New("display name must contain between 1 and 64 characters")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("display name must not contain control characters")
		}
	}
	return value, nil
}

func (s *Store) UpdateProfile(ctx context.Context, userID int64, displayName string, collaborationEnabled bool, now time.Time) (User, error) {
	name, err := ValidateDisplayName(displayName)
	if err != nil {
		return User{}, err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE portal_users SET display_name=?,collaboration_enabled=?,updated_at=? WHERE id=? AND enabled=1 AND is_admin=0`,
		name, boolInt(collaborationEnabled), now.Unix(), userID)
	if err != nil {
		return User{}, fmt.Errorf("update Portal profile: %w", err)
	}
	if err := requireChanged(result); err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, userID)
}
