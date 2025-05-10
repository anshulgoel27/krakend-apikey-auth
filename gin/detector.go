package gin

import (
	"context"
	"errors"
	"net/http"
	"os"

	auth "github.com/anshulgoel27/krakend-apikey-auth"
	"github.com/gin-gonic/gin"
	krakendjose "github.com/krakendio/krakend-jose/v2"
	ginjose "github.com/krakendio/krakend-jose/v2/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"
)

const logPrefix = "[SERVICE: Gin][apikey-auth]"

func NewApiKeyAuthenticator(ctx context.Context, cfg config.ServiceConfig, l logging.Logger) (*auth.AuthKeyLookupManager, error) {
	detectorCfg, err := auth.ParseServiceConfig(cfg.ExtraConfig)
	if err == auth.ErrNoConfig {
		return nil, err
	}
	if err != nil {
		l.Warning(logPrefix, err.Error())
		return nil, err
	}
	authManager := auth.NewAuthKeyLookupManager(detectorCfg)
	go auth.FetchAllKeys(os.Getenv("KEY_MGMT_SERVICE_HEALTH_ENDPOINT"),
		os.Getenv("KEY_MGMT_SERVICE_KEYS_ENDPOINT"), l, logPrefix, authManager)
	go auth.StartConsumer(ctx, l, logPrefix, authManager)
	return authManager, nil
}

func NewHandlerFactory(apiKeyLookupManager *auth.AuthKeyLookupManager, hf krakendgin.HandlerFactory, l logging.Logger, rejecterF krakendjose.RejecterFactory) krakendgin.HandlerFactory {
	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][apikey-auth]"
		detectorCfg, err := auth.ParseEndpointConfig(apiKeyLookupManager, cfg.ExtraConfig)
		if err == auth.ErrNoConfig {
			jwtHF := ginjose.HandlerFactory(hf, l, rejecterF)
			return jwtHF(cfg, p)
		}
		if err != nil {
			l.Warning(logPrefix, err.Error())
			jwtHF := ginjose.HandlerFactory(hf, l, rejecterF)
			return jwtHF(cfg, p)
		}

		d := auth.NewApiKeyAuthenticator(detectorCfg)

		nextApi := hf(cfg, p)

		var nextJwt gin.HandlerFunc
		_, hasJwtConfig := cfg.ExtraConfig[krakendjose.ValidatorNamespace]
		if hasJwtConfig {
			jwthf := ginjose.HandlerFactory(hf, l, rejecterF)
			nextJwt = jwthf(cfg, p)
		}

		return func(c *gin.Context) {
			valid, err := d(apiKeyLookupManager, c.Request)
			if !valid {
				if err != nil {
					l.Debug(logPrefix, err)
				}
				if hasJwtConfig && nextJwt != nil {
					if nextJwt == nil {
						l.Error(logPrefix, "JWT handler is nil despite config")
						c.AbortWithStatus(http.StatusInternalServerError)
						return
					}
					nextJwt(c)
					return
				}
				l.Error(logPrefix, errApiKeyAuthRejected)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			nextApi(c)
		}
	}
}

func handler(f auth.AuthFunc, apiKeyLookupManager *auth.AuthKeyLookupManager, next gin.HandlerFunc, l logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		valid, err := f(apiKeyLookupManager, c.Request)
		if !valid {
			if err != nil {
				l.Error(logPrefix, err)
			}
			l.Error(logPrefix, errApiKeyAuthRejected)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		next(c)
	}
}

var errApiKeyAuthRejected = errors.New("apikey auth rejected")
