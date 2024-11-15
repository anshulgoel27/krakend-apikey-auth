package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

type AuthFunc func(r *http.Request) (bool, error)

func New(cfg ApiKeyConfig) AuthFunc {
	return cfg.Auth
}

func extractCredentials(authHeader string) (username, password string, err error) {
	// Check if the header starts with "Basic "
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", fmt.Errorf("invalid authorization header")
	}

	// Extract the Base64 part of the header
	encoded := authHeader[len("Basic "):]

	// Decode the Base64 string
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Base64: %v", err)
	}

	// Split the decoded string into username and password
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid format for credentials")
	}

	// Hash the username and password separately using SHA-256
	username = sha256ToHex(parts[0])
	password = sha256ToHex(parts[1])

	return username, password, nil
}

func sha256ToHex(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func (d *ApiKeyConfig) Auth(r *http.Request) (bool, error) {
	return true, nil
}
