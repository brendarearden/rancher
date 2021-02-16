package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/mitchellh/mapstructure"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"net/http"
	"strings"
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
	return &oidcProvider{
		ctx:         ctx,
		authConfigs: mgmtCtx.Management.AuthConfigs(""),
		secrets:     mgmtCtx.Core.Secrets(""),
		oidcClient:  &oidcClient,
		userMGR:     userMGR,
		tokenMGR:    tokenMGR,
	}
}

func (o *oidcProvider) GetName() string {
	return Name
}

func (o *oidcProvider) AuthenticateUser(ctx context.Context, input interface{}) (v3.Principal, []v3.Principal, string, error) {
	login, ok := input.(*v32.OIDCLogin)
	if !ok {
		return v3.Principal{}, nil, "", fmt.Errorf("unexpected input type")
	}
	return o.LoginUser(ctx, login, nil, false)
}

func (o *oidcProvider) LoginUser(ctx context.Context, oauthLoginInfo *v32.OIDCLogin, config *v32.OIDCConfig, testAndEnableAction bool) (v3.Principal, []v3.Principal, string, error) {
	var userPrincipal v3.Principal

	if config == nil {
		config, err = o.getStoredOIDCConfig()
		if err !=nil {
			return userPrincipal, nil, "", err
		}
	}
	logrus.Debugf("[generic oidc] loginuser: using code to get oauth token")
	code := oauthLoginInfo.Code
	logrus.Debugf("[generic oidc] loginuser: exchanging code for oauth tokens")
	oauthTokens, err := o.oidcClient.getAccessTokens(code,config)
	userInfo, err := o.oidcClient.getUserInfo(oauthTokens.AccessToken, config)
	userPrincipal = o.toPrincipal(userInfo)
	logrus.Debugf("[Google OAuth] loginuser: Checking user's access to Rancher")
	allowed, err := o.userMGR.CheckAccess(config.AccessMode, config.AllowedPrincipalIDs, userPrincipal.Name, nil)
	if err != nil {
		return userPrincipal, nil, "", err
	}
	if !allowed {
		return userPrincipal, nil, "", httperror.NewAPIError(httperror.Unauthorized, "unauthorized")
	}



}

func (o *oidcProvider) SearchPrincipals(name, principalType string, myToken v3.Token) ([]v3.Principal, error) {
	return []v3.Principal{}, fmt.Errorf("generic oidc providers do not implement Search Principals")
}

func (o *oidcProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	return v3.Principal{}, fmt.Errorf("generic oidc providers do not implement Get Principals")
}

func (o *oidcProvider) CustomizeSchema(schema *types.Schema) {

}

func (o *oidcProvider) TransformToAuthProvider(authConfig map[string]interface{}) (map[string]interface{}, error) {
	panic("implement me")
}

func (o *oidcProvider) RefetchGroupPrincipals(principalID string, secret string) ([]v3.Principal, error) {
	return []v3.Principal{}, fmt.Errorf("generic oidc providers do not implement Get Principals")
}

func (o *oidcProvider) CanAccessWithGroupProviders(userPrincipalID string, groups []v3.Principal) (bool, error) {
	return false, fmt.Errorf("generic oidc providers do not implement Get Principals")
}

func (o *oidcProvider) toPrincipal (userInfo *UserInfo) v3.Principal {
		p := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: Name + "_user://" + userInfo.ObjectID},
		DisplayName:   userInfo.Profile.DisplayName,
		LoginName:     userInfo.Email,
		PrincipalType: "user",
		Provider:      Name,
	}
		return p
}

func (o *oidcProvider) saveOIDCConfig(config *v32.OIDCConfig) error {
	//storedOIDCConfig, err := o.getOIDCConfig()
	//if err != nil {
	//	return err
	//}
	//config.APIVersion = "management.cattle.io/v3"
	//config.Kind = v3.AuthConfigGroupVersionKind.Kind
	////config.Type = client
	//config.ObjectMeta = storedOIDCConfig.ObjectMeta
	//
	//field := strings.ToLower(client.AzureADConfigFieldApplicationSecret)
	//if err := common.CreateOrUpdateSecrets(o.secrets, config.ApplicationSecret, field, strings.ToLower(config.Type)); err != nil {
	//	return err
	//}
	//
	//config.ApplicationSecret = common.GetName(config.Type, field)
	//
	//logrus.Debugf("updating OIDCConfig")
	//_, err = o.authConfigs.ObjectClient().Update(config.ObjectMeta.Name, config)
	//if err != nil {
	//	return err
	//}
	return nil
}

func (o *oidcProvider) getOIDCConfig() (*v32.OIDCConfig, error) {
	authConfigObj, err := o.authConfigs.ObjectClient().UnstructuredClient().Get(Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AzureADConfig, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve OIDCConfig, cannot read k8s Unstructured data")
	}
	storedOIDCCOnfigMap := u.UnstructuredContent()

	storedOIDCConfig := &v32.OIDCConfig{}
	mapstructure.Decode(storedOIDCCOnfigMap, storedOIDCConfig)

	metadataMap, ok := storedOIDCCOnfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to retrieve OIDCConfig metadata, cannot read k8s Unstructured data")
	}

	objectMeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, objectMeta)
	storedOIDCConfig.ObjectMeta = *objectMeta

	return storedOIDCConfig, nil
}