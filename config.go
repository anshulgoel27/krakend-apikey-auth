package auth

import (
	"encoding/json"
	"errors"

	"github.com/luraproject/lura/v2/config"
)

// Namespace is the key to look for extra configuration details
const Namespace = "github_com/anshulgoel27/krakend-apikey-auth"

type ApiKey struct {
	Key             string                 `json:"key"`
	Roles           []string               `json:"roles"`
	AdditionalProps map[string]interface{} `json:"-"`
}

type ApiKeyConfig struct {
	Identifier string   `json:"identifier"`
	Keys       []ApiKey `json:"keys"`
	Strategy   string   `json:"strategy"`
}

type AuthAPIKeys struct {
	Identifier string   `json:"identifier,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Strategy   string   `json:"strategy,omitempty"`
}

var ErrNoConfig = errors.New("no config defined for the module")

func ParseServiceConfig(cfg config.ExtraConfig) (ApiKeyConfig, error) {
	res := ApiKeyConfig{}
	e, ok := cfg[Namespace]
	if !ok {
		return res, ErrNoConfig
	}
	b, err := json.Marshal(e)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(b, &res)
	return res, err
}
