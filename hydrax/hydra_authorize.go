package hydrax

import (
	"context"
	"errors"
	"log"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/nuntiodev/hera-sdks/go_hera"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/public"
	"go.uber.org/zap"
)

type HydraResponse struct {
	Id    string `json:"id"`
	Email string `json:"email"`
	Image string `json:"image"`
}

type UserInfoResponse struct {
	Aud  []string      `json:"aud"`
	Iss  string        `json:"iss"`
	User HydraResponse `json:"user"`
}

type Authorize interface {
	VerifyAndDecodeToken(token string) (*go_hera.User, error)
}

type defaultAuth struct {
	logger         *zap.Logger
	hydraClient    *client.OryHydra
	jwks           *keyfunc.JWKS
	hydraPublicUrl string
}

func New(ctx context.Context, hydraPublicUrl string, logger *zap.Logger) (Authorize, error) {
	logger.Info("creating hydra auth module")
	publicUrl, err := url.Parse(hydraPublicUrl)
	if err != nil {
		return nil, err
	}
	hydraClient := client.NewHTTPClientWithConfig(
		nil,
		&client.TransportConfig{
			Schemes:  []string{publicUrl.Scheme},
			Host:     publicUrl.Host,
			BasePath: publicUrl.Path,
		},
	)
	var hydraErr error
	var isReady *public.IsInstanceReadyOK
	for i := 0; i < 3; i++ {
		time.Sleep(time.Second * 1)
		isReady, hydraErr = hydraClient.Public.IsInstanceReady(&public.IsInstanceReadyParams{
			Context: ctx,
		})
		if hydraErr != nil {
		} else if isReady.Payload.Status != "ok" {
			hydraErr = errors.New("service is not ready")
		} else {
			break
		}
	}
	// CreateProject the keyfunc options. Refresh the JWKS every hour and log errors.
	refreshInterval := time.Hour
	options := keyfunc.Options{
		RefreshInterval: refreshInterval,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}
	if hydraErr != nil {
		return nil, hydraErr
	}
	// CreateProject the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(hydraPublicUrl+"/.well-known/jwks.json", options)
	if err != nil {
		return nil, err
	}
	defaultAuth := &defaultAuth{
		logger:         logger,
		hydraClient:    hydraClient,
		jwks:           jwks,
		hydraPublicUrl: hydraPublicUrl,
	}
	return defaultAuth, nil
}

func (da *defaultAuth) VerifyAndDecodeToken(accessToken string) (*go_hera.User, error) {
	if accessToken == "" {
		return nil, errors.New("access token is empty")
	}
	token, err := jwt.Parse(accessToken, da.jwks.Keyfunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("could not extract claims")
	}
	userId, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("userid is empty")
	}
	email, _ := claims["email"].(string)

	return &go_hera.User{
		Id:    userId,
		Email: &email,
	}, nil
}
