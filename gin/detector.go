package gin

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/anshulgoel27/krakend-apikey-auth"
	"github.com/gin-gonic/gin"
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
	go auth.StartConsumer(ctx, l, logPrefix, authManager)
	return authManager, nil
}

func NewHandlerFactory(apiKeyLookupManager *auth.AuthKeyLookupManager, hf krakendgin.HandlerFactory, l logging.Logger) krakendgin.HandlerFactory {
	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		next := hf(cfg, p)
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][apikey-auth]"

		detectorCfg, err := auth.ParseEndpointConfig(apiKeyLookupManager, cfg.ExtraConfig)
		if err == auth.ErrNoConfig {
			return next
		}
		if err != nil {
			l.Warning(logPrefix, err.Error())
			return next
		}

		d := auth.NewApiKeyAuthenticator(detectorCfg)
		return handler(d, apiKeyLookupManager, next, l)
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
