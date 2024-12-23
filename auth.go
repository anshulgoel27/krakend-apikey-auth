package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

const (
	AuthorizationBearer = "Bearer "
	AuthorizationBasic  = "Basic "
)

type AuthFunc func(apiKeyLookupManager *AuthKeyLookupManager, r *http.Request) (bool, error)

func NewApiKeyAuthenticator(cfg EndpointApiKeyConfig) AuthFunc {
	return cfg.Authenticate
}

func sha256ToHex(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func (d *EndpointApiKeyConfig) Authenticate(apiKeyLookupManager *AuthKeyLookupManager, r *http.Request) (bool, error) {
	var apiKey string

	// Determine the strategy for extracting the API key
	if d.Strategy == "" || d.Strategy == Header {
		// Default behavior: Extract API key from the Authorization header (Bearer or Basic)
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if len(authHeader) > len(AuthorizationBearer) && authHeader[:len(AuthorizationBearer)] == AuthorizationBearer {
				// Remove the "Bearer " prefix and take the rest as the API key
				apiKey = authHeader[len(AuthorizationBearer):]
			} else if len(authHeader) > len(AuthorizationBasic) && authHeader[:len(AuthorizationBasic)] == AuthorizationBasic {
				// Remove the "Basic " prefix, decode the base64 part, and take the result as the API key
				encoded := authHeader[len(AuthorizationBasic):]
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return false, fmt.Errorf("invalid base64 encoding in Authorization header: %v", err)
				}
				// The base64 decoded value will be in the format "<api_key>:"
				// So, strip the trailing colon
				apiKey = strings.Split(string(decoded), ":")[0]
			} else {
				// No valid prefix, treat the whole header value as the API key
				apiKey = authHeader
			}
		} else {
			return false, fmt.Errorf("authorization header missing")
		}
	} else if d.Strategy == QueryString {
		// Extract API key from query string
		apiKey = r.URL.Query().Get(d.Identifier)
		if apiKey == "" {
			return false, fmt.Errorf("API key missing in query string (%s)", d.Identifier)
		}
	} else {
		// Invalid strategy
		return false, fmt.Errorf("unknown strategy: %s", d.Strategy)
	}

	// Validate the API key and its roles
	valid, propagate_role, err := apiKeyLookupManager.ValidateKeyAndRoles(sha256ToHex(apiKey), d.Roles)
	if err != nil {
		return false, fmt.Errorf("authentication failed for API key: %v", err)
	}

	if apiKeyLookupManager.PropagateRoleHeader() != "" {
		r.Header.Set(apiKeyLookupManager.PropagateRoleHeader(), propagate_role)
	}

	// Return the result of validation
	return valid, nil
}
