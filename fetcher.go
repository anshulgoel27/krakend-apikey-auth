package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/luraproject/lura/v2/logging"
)

func FetchAllKeys(health_endpoint string, keys_endpoint string, l logging.Logger,
	logPrefix string, authManager *AuthKeyLookupManager) {
	if health_endpoint != "" && keys_endpoint != "" {
		maxRetries := 10
		for i := 0; i < maxRetries; i++ {
			err := checkHealth(health_endpoint)
			if err != nil {
				l.Debug(logPrefix, "auth service is not healthy, will retry after 1 second", err)
				time.Sleep(1 * time.Second) // Wait before retrying
			} else {
				l.Debug(logPrefix, "auth service is up")
				//fetch keys
				offset := 0
				for {
					url := fmt.Sprintf("%s?offset=%d&limit=%d", keys_endpoint, offset, 1000)
					keys, err := fetchKeys(url)
					if err != nil {
						l.Error("fetchAllKeys", "failed to fetch keys", err)
						return
					}

					if len(keys.Keys) == 0 {
						l.Debug("fetchAllKeys", "No more keys to fetch, stopping pagination")
						break
					}

					for _, key := range keys.Keys {
						ok, err := authManager.addKey(&key)
						if !ok {
							if err != nil {
								l.Debug(logPrefix, "Key creation failed", key, err.Error())
							}
						} else {
							l.Debug(logPrefix, "Key created", key)
						}
					}
				}
				return
			}
		}
		l.Debug(logPrefix, "auth service health check failed after maximum retries")
	} else {
		l.Error(logPrefix, "env KEY_MGMT_SERVICE_HEALTH_ENDPOINT and KEY_MGMT_SERVICE_KEYS_ENDPOINT not defined")
	}
}

func fetchKeys(url string) (CreatedEvent, error) {
	client := &http.Client{
		Timeout: 5 * time.Second, // Adjust the timeout as needed
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys: %w", err)
	}
	defer resp.Body.Close()

	// Check for HTTP success
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch keys, status code: %d", resp.StatusCode)
	}

	// Parse the response body
	var keys CreatedEvent
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode keys response: %w", err)
	}

	return keys, nil
}

func checkHealth(url string) error {
	client := &http.Client{
		Timeout: 50 * time.Millisecond, // Set a timeout for the request
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make GET request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the status code indicates success
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed, status code: %d", resp.StatusCode)
	}

	return nil
}
