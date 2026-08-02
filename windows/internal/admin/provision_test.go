package admin

import (
	"bytes"
	"testing"
	"unicode"
)

func TestGenerateWindowsPasswordIsRandomAndMeetsRequiredClasses(t *testing.T) {
	first, err := generateWindowsPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateWindowsPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || bytes.Equal(first, second) {
		t.Fatalf("generated passwords are invalid or unexpectedly equal")
	}
	var upper, lower, digit, symbol bool
	for _, character := range string(first) {
		upper = upper || unicode.IsUpper(character)
		lower = lower || unicode.IsLower(character)
		digit = digit || unicode.IsDigit(character)
		symbol = symbol || !unicode.IsLetter(character) && !unicode.IsDigit(character)
	}
	if !upper || !lower || !digit || !symbol {
		t.Fatalf("generated password lacks a required character class")
	}
}
