package gin

import (
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

func Register(cfg config.ServiceConfig, l logging.Logger, engine *gin.Engine) {
	detectorCfg, err := auth.ParseServiceConfig(cfg.ExtraConfig)
	if err == auth.ErrNoConfig {
		return
	}
	if err != nil {
		l.Warning(logPrefix, err.Error())
		return
	}
	d := auth.New(detectorCfg)
	engine.Use(middleware(d, l))
}

func middleware(f auth.AuthFunc, l logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		valid, err := f(c.Request)
		if !valid {
			if err != nil {
				l.Error(logPrefix, err)
			}
			l.Error(logPrefix, errApiKeyAuthRejected)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

func New(hf krakendgin.HandlerFactory, l logging.Logger) krakendgin.HandlerFactory {
	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		next := hf(cfg, p)
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][apikey-auth]"

		detectorCfg, err := auth.ParseServiceConfig(cfg.ExtraConfig)
		if err == auth.ErrNoConfig {
			return next
		}
		if err != nil {
			l.Warning(logPrefix, err.Error())
			return next
		}

		d := auth.New(detectorCfg)
		return handler(d, next, l)
	}
}

func handler(f auth.AuthFunc, next gin.HandlerFunc, l logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		valid, err := f(c.Request)
		if !valid {
			if err != nil {
				l.Error(logPrefix, err)
			}
			l.Error(logPrefix, errApiKeyAuthRejected)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		next(c)
	}
}

var errApiKeyAuthRejected = errors.New("apikey auth rejected")
