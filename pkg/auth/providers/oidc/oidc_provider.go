package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/rancher/norman/types"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"

	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/user"
	"golang.org/x/oauth2"
)

const (
	Name = "oidc"
)

type oidcProvider struct {
	ctx         context.Context
	authConfigs v3.AuthConfigInterface
	secrets     corev1.SecretInterface
	oidcClient  *OIDCClient
	userMGR     user.Manager
	tokenMGR    *tokens.Manager
}

func Configure(ctx context.Context, mgmtCtx *config.ScaledContext, userMGR user.Manager, tokenMGR *tokens.Manager) common.AuthProvider {
	oidcClient := OIDCClient{
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
	return &oidcProvider {
		ctx:         ctx,
		authConfigs: mgmtCtx.Management.AuthConfigs(""),
		secrets:     mgmtCtx.Core.Secrets(""),
		oidcClient:  &oidcClient,
		userMGR:     userMGR,
		tokenMGR:    tokenMGR,
	}
}



func (o oidcProvider) GetName() string {
	return Name
}

func (o oidcProvider) AuthenticateUser(ctx context.Context, input interface{}) (v3.Principal, []v3.Principal, string, error) {
	login, ok := input.(*v32.)
	if !ok {
		return v3.Principal{}, nil, "", fmt.Errorf("unexpected input type")
	}
	return o.LoginUser(ctx, login, nil, false)
}

func (o oidcProvider) LoginUser(ctx context.Context, oauthLoginInfo *v32.GenericOIDCLogin, config *v32.OIDCConfig, testAndEnableAction bool) (v3.Principal, string, error) {
	var userPrincipal v3.Principal

	if config == nil {
		config, err = o.getStoredOIDCConfig()
		if err !=nil {
			return userPrincipal, "", err
		}
	}

	logrus.Debugf("[Generic OIDC] loginuser: Using code to get oauth token")
	code := oauthLoginInfo.Code
	oauthConfig, err :=

}

func (o oidcProvider) SearchPrincipals(name, principalType string, myToken v3.Token) ([]v3.Principal, error) {
	return v3.Principal{}, fmt.Errorf("Generic OIDC providers do not implement Search Principals")
}

func (o oidcProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	return v3.Principal{}, fmt.Errorf("Generic OIDC providers do not implement Get Principals")
}

func (o oidcProvider) CustomizeSchema(schema *types.Schema) {

}

func (o oidcProvider) TransformToAuthProvider(authConfig map[string]interface{}) (map[string]interface{}, error) {
	panic("implement me")
}

func (o oidcProvider) RefetchGroupPrincipals(principalID string, secret string) ([]v3.Principal, error) {
	panic("implement me")
}

func (o oidcProvider) CanAccessWithGroupProviders(userPrincipalID string, groups []v3.Principal) (bool, error) {
	panic("implement me")
}