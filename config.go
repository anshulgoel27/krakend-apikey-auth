package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/luraproject/lura/v2/config"
)

// Define enum for Strategy
type ApiKeyStrategy string

const (
	Header      ApiKeyStrategy = "header"
	QueryString ApiKeyStrategy = "query_string"
)

// Default values
const defaultStrategy = Header
const defaultIdentifier = "X-API-Key"
const defaultPropagateRoleHeader = "X-API-Role"

// Namespace is the key to look for extra configuration details
const Namespace = "github_com/anshulgoel27/krakend-apikey-auth"

// ApiKey structure with a persistent role map
type ApiKey struct {
	Key             string                 `json:"key"`
	Roles           []string               `json:"roles"`           // Roles as a slice
	ExpirationDate  time.Time              `json:"expiration_date"` // Expiration date for API key
	CreationDate    time.Time              `json:"creation_date"`   // Creation date for API key
	UserId          string                 `json:"user_id"`
	UserEmail       string                 `json:"user_email"`
	OrgID           string                 `json:"org_id"`
	OrgName         string                 `json:"org_name"`
	Enabled         bool                   `json:"enabled"`
	RoleMap         map[string]struct{}    `json:"-"` // RoleMap for fast lookup
	AdditionalProps map[string]interface{} `json:"-"`
}

// Method to initialize the RoleMap field for ApiKey
func (apiKey *ApiKey) initializeRoleMap() {
	if apiKey.RoleMap == nil {
		apiKey.RoleMap = make(map[string]struct{})
	}
	for _, role := range apiKey.Roles {
		apiKey.RoleMap[role] = struct{}{}
	}
}

// Method to check if an ApiKey has a specific role (uses RoleMap)
func (apiKey *ApiKey) hasRole(role string) bool {
	if apiKey.RoleMap == nil {
		// Ensure RoleMap is initialized if not already
		apiKey.initializeRoleMap()
	}
	_, found := apiKey.RoleMap[role]
	return found
}

// Function to check if an API key is expired
func (apiKey *ApiKey) isExpired() bool {
	// Check if expiration date is non-zero and in the past
	return !apiKey.ExpirationDate.IsZero() && apiKey.ExpirationDate.Before(time.Now())
}

// ServiceApiKeyConfig structure remains unchanged
type ServiceApiKeyConfig struct {
	// The header name or the query string name that contains the API key. Defaults to key when using the query_string strategy and to Authorization when using the header strategy. The identifier set here is used across all endpoints with API key authentication enabled, but they can override this entry individually.
	// Examples: "Authorization" , "X-Key"
	// Defaults to "Authorization"
	Identifier string `json:"identifier,omitempty"`
	// Specifies where to expect the user API key, whether inside a header or as part of the query string. The strategy set here is used across all endpoints with API key authentication enabled, but they can override this entry individually.
	// Possible values are: "header" , "query_string"
	// Defaults to "header"
	Strategy ApiKeyStrategy `json:"strategy,omitempty"`
	// The name of a header that will propagate to the backend containing the matching role.
	// The backend receives no header when the string is empty, or the attribute is not declared.
	// Otherwise, the backend receives the declared header name containing the first matching role of the user.
	// The header value will be ANY when the endpoint does not require roles. For instance, if an API key has roles [A, B],
	// and the endpoint demands roles [B, C], the backend will receive a header with the value B.
	// Default X-API-Role
	PropagateRole string   `json:"propagate_role,omitempty"`
	Keys          []ApiKey `json:"keys"`
	AdminKeyEnv   string   `json:"admin_key_env"`
}

// Build a lookup map for ApiKey
// Thread-safe map creation
func (manager *AuthKeyLookupManager) buildKeyLookup(keys []ApiKey) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, key := range keys {
		manager.lookupKeyMap[key.Key] = key
	}
}

// AuthKeyLookupManager class with added role-based lookup
type AuthKeyLookupManager struct {
	lookupKeyMap        map[string]ApiKey
	defaultIdentifier   string
	defaultStrategy     ApiKeyStrategy
	propagateRoleHeader string
	mu                  sync.RWMutex // Mutex for thread-safe access
}

// Constructor for LookupManager
func NewAuthKeyLookupManager(config ServiceApiKeyConfig) *AuthKeyLookupManager {
	// Initialize RoleMap for each ApiKey instance at creation
	for i := range config.Keys {
		config.Keys[i].initializeRoleMap()
	}

	manager := &AuthKeyLookupManager{
		lookupKeyMap:        make(map[string]ApiKey),
		defaultIdentifier:   config.Identifier,
		defaultStrategy:     config.Strategy,
		propagateRoleHeader: config.PropagateRole,
	}

	// Build the lookup map in a thread-safe manner
	manager.buildKeyLookup(config.Keys)

	return manager
}

func (manager *AuthKeyLookupManager) DefaultIdentifier() string {
	return manager.defaultIdentifier
}

func (manager *AuthKeyLookupManager) PropagateRoleHeader() string {
	return manager.propagateRoleHeader
}

func (manager *AuthKeyLookupManager) DefautlStrategy() ApiKeyStrategy {
	return manager.defaultStrategy
}

// Lookup function to find an ApiKey by key
func (manager *AuthKeyLookupManager) lookupKey(key string) (ApiKey, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	apiKey, found := manager.lookupKeyMap[key]
	return apiKey, found
}

func (manager *AuthKeyLookupManager) deleteKey(key string) (ApiKey, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	apiKey, exists := manager.lookupKeyMap[key]
	if exists {
		delete(manager.lookupKeyMap, key)
		return apiKey, true
	}
	return ApiKey{}, false
}

func (manager *AuthKeyLookupManager) updateKey(key string, enable bool, planName string) (ApiKey, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	apiKey, exists := manager.lookupKeyMap[key]
	if exists {
		apiKey.Enabled = enable
		apiKey.Roles = []string{planName}
		apiKey.RoleMap = nil
		return apiKey, true
	}
	return ApiKey{}, false
}

func (manager *AuthKeyLookupManager) addKey(keyData *CreatedKeyData) (bool, error) {

	if keyData.Key == "" || keyData.Email == "" || keyData.UserID == "" {
		return false, fmt.Errorf("key %v has missing attributes", keyData)
	}

	newKey := ApiKey{
		Key:            keyData.Key,
		UserEmail:      keyData.Email,
		UserId:         keyData.UserID,
		ExpirationDate: keyData.ExpirationDate,
		CreationDate:   keyData.CreationDate,
		Enabled:        keyData.Enabled,
		OrgID:          keyData.OrgID,
		OrgName:        keyData.OrgName,
		Roles: []string{
			keyData.Plan,
		},
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// Check if the key already exists
	if _, exists := manager.lookupKeyMap[newKey.Key]; exists {
		return false, fmt.Errorf("key %v already exists", keyData) // Key already exists
	}

	// Add the new key to the map
	manager.lookupKeyMap[newKey.Key] = newKey
	return true, nil
}

// Method to validate if the key and role are valid
func (manager *AuthKeyLookupManager) ValidateKeyAndRole(key string, role string) (bool, error) {
	// Lookup the ApiKey by the provided key
	apiKey, found := manager.lookupKey(key)
	if !found {
		return false, errors.New("API key not found")
	}

	// Check if the API key is enabled or not
	if !apiKey.Enabled {
		return false, fmt.Errorf("API key '%s' is disabled", key)
	}

	// Check if the API key is expired
	if apiKey.isExpired() {
		return false, fmt.Errorf("API key '%s' has expired", key)
	}

	// Check if the ApiKey has the specified role
	if !apiKey.hasRole(role) {
		return false, fmt.Errorf("role '%s' not found for API key '%s'", role, key)
	}

	// Both key and role are valid
	return true, nil
}

// Method to validate if the key and any role from the list are valid
func (manager *AuthKeyLookupManager) ValidateKeyAndRoles(key string, roles []string) (bool, string, ApiKey, error) {
	// Lookup the ApiKey by the provided key
	apiKey, found := manager.lookupKey(key)
	if !found {
		return false, "", ApiKey{}, errors.New("API key not found")
	}

	// Check if the API key is enabled or not
	if !apiKey.Enabled {
		return false, "", ApiKey{}, fmt.Errorf("API key '%s' is disabled", key)
	}

	// Check if the API key is expired
	if apiKey.isExpired() {
		return false, "", ApiKey{}, fmt.Errorf("API key '%s' has expired", key)
	}

	// Iterate through the list of roles and check if any of them are found in the RoleMap
	for _, role := range roles {
		if apiKey.hasRole(role) {
			// Role found
			return true, role, apiKey, nil
		}
	}

	// No valid role found
	return false, "", ApiKey{}, fmt.Errorf("none of the roles %v found for API key '%s'", roles, key)
}

type EndpointApiKeyConfig struct {
	Roles []string `json:"roles,omitempty"`
	// The header name or the query string name that contains the API key. Defaults to key when using the query_string strategy and to Authorization when using the header strategy. The identifier set here is used across all endpoints with API key authentication enabled, but they can override this entry individually.
	// Examples: "Authorization" , "X-Key"
	// Defaults to "Authorization"
	Identifier string `json:"identifier,omitempty"`
	// Specifies where to expect the user API key, whether inside a header or as part of the query string. The strategy set here is used across all endpoints with API key authentication enabled, but they can override this entry individually.
	// Possible values are: "header" , "query_string"
	// Defaults to "header"
	Strategy ApiKeyStrategy `json:"strategy,omitempty"`
}

var ErrNoConfig = errors.New("no config defined for the module")

func ParseServiceConfig(cfg config.ExtraConfig) (ServiceApiKeyConfig, error) {
	res := ServiceApiKeyConfig{}
	e, ok := cfg[Namespace]
	if !ok {
		return res, ErrNoConfig
	}
	b, err := json.Marshal(e)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(b, &res)

	// Set defaults if not provided
	if res.Identifier == "" {
		res.Identifier = defaultIdentifier
	}
	if res.Strategy == "" {
		res.Strategy = defaultStrategy
	}
	if res.PropagateRole == "" {
		res.PropagateRole = defaultPropagateRoleHeader
	}

	if res.AdminKeyEnv != "" {
		admin_key := os.Getenv(res.AdminKeyEnv)
		if admin_key != "" {
			hased_admin_key := sha256ToHex(admin_key)
			res.Keys = append(res.Keys, ApiKey{
				Key: hased_admin_key,
				Roles: []string{
					"admin",
				},
				CreationDate: time.Now(),
				UserId:       "admin",
				UserEmail:    "admin",
				OrgID:        "admin",
				OrgName:      "admin",
				Enabled:      true,
			})
		}
	}

	return res, err
}

func ParseEndpointConfig(apiKeyLookupManager *AuthKeyLookupManager, cfg config.ExtraConfig) (EndpointApiKeyConfig, error) {
	res := EndpointApiKeyConfig{}
	e, ok := cfg[Namespace]
	if !ok {
		return res, ErrNoConfig
	}
	b, err := json.Marshal(e)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(b, &res)

	// Set defaults if not provided
	if res.Identifier == "" {
		res.Identifier = apiKeyLookupManager.DefaultIdentifier()
	}
	if res.Strategy == "" {
		res.Strategy = apiKeyLookupManager.DefautlStrategy()
	}

	return res, err
}
