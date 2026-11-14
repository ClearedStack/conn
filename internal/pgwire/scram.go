package pgwire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const (
	scramMechanism = "SCRAM-SHA-256"
	minSCRAMIters  = 1
	maxSCRAMIters  = 1_000_000
)

type scramClient struct {
	password        string
	clientNonce     string
	clientFirstBare string
	serverFirst     string
	expectedSrvSig  []byte
}

func newSCRAMClient(password string, customNonce string) (*scramClient, error) {
	nonce := customNonce
	if nonce == "" {
		var raw [18]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, errors.New("scram: failed to generate nonce")
		}
		nonce = base64.StdEncoding.EncodeToString(raw[:])
	}
	bare := "n=,r=" + nonce
	return &scramClient{
		password:        password,
		clientNonce:     nonce,
		clientFirstBare: bare,
	}, nil
}

// clientFirst returns the GS2-prefixed client-first-message ("n,,n=,r=<nonce>").
func (s *scramClient) clientFirst() []byte {
	return []byte("n,," + s.clientFirstBare)
}

// stepContinue processes AuthenticationSASLContinue ("r=...,s=...,i=...") and
// returns the client-final-message ("c=biws,r=...,p=...").
func (s *scramClient) stepContinue(serverFirstBytes []byte) ([]byte, error) {
	serverFirst := string(serverFirstBytes)
	s.serverFirst = serverFirst

	var combinedNonce, saltB64 string
	var iterStr string
	for _, part := range strings.Split(serverFirst, ",") {
		switch {
		case strings.HasPrefix(part, "r="):
			combinedNonce = part[2:]
		case strings.HasPrefix(part, "s="):
			saltB64 = part[2:]
		case strings.HasPrefix(part, "i="):
			iterStr = part[2:]
		case strings.HasPrefix(part, "m="):
			return nil, errors.New("scram: unsupported mandatory extension")
		}
	}
	if combinedNonce == "" || !strings.HasPrefix(combinedNonce, s.clientNonce) || len(combinedNonce) == len(s.clientNonce) {
		return nil, errors.New("scram: invalid server nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("scram: invalid salt")
	}
	iters, err := strconv.Atoi(iterStr)
	if err != nil || iters < minSCRAMIters || iters > maxSCRAMIters {
		return nil, errors.New("scram: invalid iteration count")
	}

	saltedPassword := pbkdf2SHA256([]byte(s.password), salt, iters)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalWithoutProof := "c=biws,r=" + combinedNonce
	authMessage := s.clientFirstBare + "," + s.serverFirst + "," + clientFinalWithoutProof

	clientSig := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}

	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	s.expectedSrvSig = hmacSHA256(serverKey, []byte(authMessage))

	finalMsg := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)
	return []byte(finalMsg), nil
}

// stepFinal verifies AuthenticationSASLFinal ("v=<base64ServerSignature>").
func (s *scramClient) stepFinal(serverFinalBytes []byte) error {
	serverFinal := string(serverFinalBytes)
	var verifierB64 string
	for _, part := range strings.Split(serverFinal, ",") {
		if strings.HasPrefix(part, "v=") {
			verifierB64 = part[2:]
		} else if strings.HasPrefix(part, "e=") {
			return errors.New("scram: server rejected authentication")
		}
	}
	if verifierB64 == "" {
		return errors.New("scram: missing server signature")
	}
	gotSig, err := base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		return errors.New("scram: malformed server signature")
	}
	if !hmac.Equal(gotSig, s.expectedSrvSig) {
		return errors.New("scram: server signature mismatch")
	}
	return nil
}

// pbkdf2SHA256 derives a 32-byte key (1 SHA-256 block) per RFC 2898 / RFC 5802 Hi().
func pbkdf2SHA256(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	var blockIdx [4]byte
	binary.BigEndian.PutUint32(blockIdx[:], 1)
	mac.Write(blockIdx[:])
	u := mac.Sum(nil)
	out := make([]byte, len(u))
	copy(out, u)

	for i := 2; i <= iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
