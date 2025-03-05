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
	AuthorizationHeader = "Authorization"
	AuthorizationBearer = "Bearer "
	AuthorizationBasic  = "Basic "
	UserIdHeader        = "X-User-Id"
	UserEmailHeader     = "X-User-Email"
	OrgIdHeader         = "X-Org-Id"
	OrgNameHeader       = "X-Org-Name"
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
		authHeaderValue := r.Header.Get(AuthorizationHeader)
		if authHeaderValue == "" {
			if d.Identifier != "" {
				authHeaderValue = r.Header.Get(d.Identifier)
			}
			if authHeaderValue == "" {
				return false, fmt.Errorf("authorization header missing")
			}
		}

		if strings.HasPrefix(authHeaderValue, AuthorizationBearer) {
			apiKey = strings.TrimPrefix(authHeaderValue, AuthorizationBearer)
		} else if strings.HasPrefix(authHeaderValue, AuthorizationBasic) {
			encoded := strings.TrimPrefix(authHeaderValue, AuthorizationBasic)
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return false, fmt.Errorf("invalid base64 encoding: %v", err)
			}
			apiKey = strings.SplitN(string(decoded), ":", 2)[0]
		} else {
			apiKey = authHeaderValue
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
	valid, propagate_role, api_key, err := apiKeyLookupManager.ValidateKeyAndRoles(sha256ToHex(apiKey), d.Roles)
	if err != nil {
		return false, fmt.Errorf("authentication failed for API key: %v", err)
	}

	if apiKeyLookupManager.PropagateRoleHeader() != "" {
		r.Header.Set(apiKeyLookupManager.PropagateRoleHeader(), propagate_role)
	}

	r.Header.Set(UserIdHeader, api_key.UserId)
	r.Header.Set(UserEmailHeader, api_key.UserEmail)
	r.Header.Set(OrgIdHeader, api_key.OrgID)
	r.Header.Set(OrgNameHeader, api_key.OrgName)

	// Return the result of validation
	return valid, nil
}
