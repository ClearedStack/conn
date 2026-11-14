// Package pow verifies and solves Muster Contract v1 proof-of-work puzzles.
//
// Both anonymous edit proposals (POST /v1/edits) and visitor tool suggestions
// (POST /v1/items with source "site-form") require a token "<day>.<nonce>"
// where SHA-256("muster-pow-v1\x00" + day + "\x00" + a + "\x00" + b + "\x00" + c + "\x00" + nonce)
// starts with at least Difficulty leading zero bits, and day is today or
// yesterday in UTC.
package pow

import (
	"crypto/sha256"
	"errors"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

const (
	// Label is the Contract v1 domain separator prefix.
	Label = "muster-pow-v1"

	// DefaultDifficulty is the required leading zero bit count in Contract v1.
	DefaultDifficulty = 20

	// DayLayout is the UTC date layout used in proof-of-work tokens.
	DayLayout = "2006-01-02"
)

// Verify reports whether token solves the proof-of-work puzzle for (a, b, c)
// with at least difficulty leading zero bits at time now (today or yesterday UTC).
func Verify(token, a, b, c string, difficulty int, now time.Time) bool {
	if difficulty < 0 || difficulty > 256 {
		return false
	}
	day, nonce, ok := splitToken(token)
	if !ok {
		return false
	}
	utcNow := now.UTC()
	today := utcNow.Format(DayLayout)
	yesterday := utcNow.AddDate(0, 0, -1).Format(DayLayout)
	if day != today && day != yesterday {
		return false
	}
	sum := Digest(day, a, b, c, nonce)
	return LeadingZeroBits(sum) >= difficulty
}

// Solve searches deterministically for a lowercase hexadecimal nonce so that
// "<day>.<nonce>" has at least difficulty leading zero bits for (a, b, c).
// Intended for tests and stand-in harnesses.
func Solve(day, a, b, c string, difficulty int) (string, error) {
	if difficulty < 0 || difficulty > 32 {
		return "", errors.New("pow: difficulty out of range")
	}
	if !validDay(day) {
		return "", errors.New("pow: day must be YYYY-MM-DD")
	}
	for n := uint64(0); ; n++ {
		nonce := strconv.FormatUint(n, 16)
		sum := Digest(day, a, b, c, nonce)
		if LeadingZeroBits(sum) >= difficulty {
			return day + "." + nonce, nil
		}
	}
}

// Digest computes SHA-256("muster-pow-v1\x00" + day + "\x00" + a + "\x00" + b + "\x00" + c + "\x00" + nonce).
func Digest(day, a, b, c, nonce string) [sha256.Size]byte {
	h := sha256.New()
	var zero [1]byte
	for _, part := range [5]string{Label, day, a, b, c} {
		h.Write([]byte(part))
		h.Write(zero[:])
	}
	h.Write([]byte(nonce))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// LeadingZeroBits counts the leading zero bits in a 32-byte SHA-256 digest.
func LeadingZeroBits(sum [sha256.Size]byte) int {
	total := 0
	for _, b := range sum {
		if b != 0 {
			return total + bits.LeadingZeros8(b)
		}
		total += 8
	}
	return total
}

func splitToken(token string) (day, nonce string, ok bool) {
	dot := strings.IndexByte(token, '.')
	if dot != 10 {
		return "", "", false
	}
	day = token[:dot]
	nonce = token[dot+1:]
	if !validDay(day) || len(nonce) < 1 || len(nonce) > 32 {
		return "", "", false
	}
	for i := 0; i < len(nonce); i++ {
		ch := nonce[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return "", "", false
		}
	}
	return day, nonce, true
}

func validDay(day string) bool {
	if len(day) != 10 || day[4] != '-' || day[7] != '-' {
		return false
	}
	for _, idx := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
		if day[idx] < '0' || day[idx] > '9' {
			return false
		}
	}
	return true
}
