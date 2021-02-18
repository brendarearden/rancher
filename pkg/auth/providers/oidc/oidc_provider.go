package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	publicclient "github.com/rancher/rancher/pkg/client/generated/management/v3public"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/user"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	Name = "oidc"
)

type oidcProvider struct {
	ctx         context.Context
	authConfigs v3.AuthConfigInterface
	secrets     corev1.SecretInterface
	oidcClient  *Client
	userMGR     user.Manager
	tokenMGR    *tokens.Manager
}

func Configure(ctx context.Context, mgmtCtx *config.ScaledContext, userMGR user.Manager, tokenMGR *tokens.Manager) common.AuthProvider {
	oidcClient := Client{
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
	return o.LoginUser(login, nil, false)
}

func (o *oidcProvider) LoginUser(oauthLoginInfo *v32.OIDCLogin, config *v32.OIDCConfig, testAndEnableAction bool) (v3.Principal, []v3.Principal, string, error) {
	var userPrincipal v3.Principal
	//var cert *x509.Certificate
	var err error

	if config == nil {
		config, err = o.getOIDCConfig()
		if err != nil {
			return userPrincipal, nil, "", err
		}
	}
	logrus.Debugf("[generic oidc] loginuser: using code to get oauth token")
	code := oauthLoginInfo.Code
	//logrus.Debugf("[generic oidc] loginuser: exchanging code for oauth tokens")
	//if config.Certificate != "" {
	//	block, _ := pem.Decode([]byte(config.Certificate))
	//	if block == nil {
	//		return userPrincipal, nil, "", fmt.Errorf("[generic oidc] loginuser: failed to parse PEM block containing the private key")
	//	}
	//
	//	cert, err = x509.ParseCertificate(block.Bytes)
	//	if err != nil {
	//		return userPrincipal, nil, "", fmt.Errorf("[generic oidc] loginuser: failed to parse DER encoded public key: " + err.Error())
	//	}
	//}
	//keyPair := tls.Certificate{
	//	Certificate: [][]byte{cert.Raw},
	//	PrivateKey:  config.PrivateKey,
	//	Leaf:        cert,
	//}
	oauthTokens, err := o.oidcClient.getAccessTokens(code, config)
	userInfo, err := o.oidcClient.getUserInfo(oauthTokens.AccessToken, config)
	userPrincipal = o.toPrincipal(userInfo)
	logrus.Debugf("[generic oidc] loginuser: Checking user's access to Rancher")
	allowed, err := o.userMGR.CheckAccess(config.AccessMode, config.AllowedPrincipalIDs, userPrincipal.Name, nil)
	if err != nil {
		return userPrincipal, nil, "", err
	}
	if !allowed {
		return userPrincipal, nil, "", httperror.NewAPIError(httperror.Unauthorized, "unauthorized")
	}
	return userPrincipal, nil, "", nil
}

func (o *oidcProvider) SearchPrincipals(name, principalType string, myToken v3.Token) ([]v3.Principal, error) {
	return []v3.Principal{}, fmt.Errorf("[generic oidc] providers do not implement Search Principals")
}

func (o *oidcProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	return v3.Principal{}, fmt.Errorf("[generic oidc] providers do not implement Get Principals")
}

func (o *oidcProvider) CustomizeSchema(schema *types.Schema) {
	schema.ActionHandler = o.actionHandler
	schema.Formatter = o.formatter
}

func (o *oidcProvider) TransformToAuthProvider(authConfig map[string]interface{}) (map[string]interface{}, error) {
	p := common.TransformToAuthProvider(authConfig)
	p[publicclient.OIDCProviderFieldRedirectURL] = o.getRedirectURL(authConfig)
	return p, nil
}

func (o *oidcProvider) getRedirectURL(config map[string]interface{}) string {
	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s",
		config["authEndpoint"],
		config["clientId"],
		config["rancherUrl"],
	)
}

func (o *oidcProvider) RefetchGroupPrincipals(principalID string, secret string) ([]v3.Principal, error) {
	return []v3.Principal{}, fmt.Errorf("[generic oidc]: does not implement Get Principals")
}

func (o *oidcProvider) CanAccessWithGroupProviders(userPrincipalID string, groupPrincipals []v3.Principal) (bool, error) {
	config, err := o.getOIDCConfig()
	if err != nil {
		logrus.Errorf("[generic oidc]: error fetching OIDCConfig: %v", err)
		return false, err
	}
	allowed, err := o.userMGR.CheckAccess(config.AccessMode, config.AllowedPrincipalIDs, userPrincipalID, groupPrincipals)
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (o *oidcProvider) toPrincipal(userInfo *UserInfo) v3.Principal {
	p := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: Name + "_user://" + userInfo.Subject},
		DisplayName:   userInfo.Email,
		LoginName:     userInfo.Email,
		PrincipalType: "user",
		Provider:      Name,
	}
	return p
}

func (o *oidcProvider) saveOIDCConfig(config *v32.OIDCConfig) error {
	storedOidcConfig, err := o.getOIDCConfig()
	if err != nil {
		return err
	}
	config.APIVersion = "management.cattle.io/v3"
	config.Kind = v3.AuthConfigGroupVersionKind.Kind
	config.Type = client.OIDCConfigType
	config.ObjectMeta = storedOidcConfig.ObjectMeta

	if config.PrivateKey != "" {
		field := strings.ToLower(client.OIDCConfigFieldPrivateKey)
		if err = common.CreateOrUpdateSecrets(o.secrets, config.PrivateKey, field, strings.ToLower(config.Type)); err != nil {
			return err
		}
		config.PrivateKey = common.GetName(config.Type, field)
	}

	logrus.Debugf("[generic oidc] updating config")
	_, err = o.authConfigs.ObjectClient().Update(config.ObjectMeta.Name, config)
	return err
}

func (o *oidcProvider) getOIDCConfig() (*v32.OIDCConfig, error) {
	authConfigObj, err := o.authConfigs.ObjectClient().UnstructuredClient().Get(Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("[generic oidc]: failed to retrieve OIDCConfig, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, fmt.Errorf("[generic oidc]: failed to retrieve OIDCConfig, cannot read k8s Unstructured data")
	}
	storedOidcConfigMap := u.UnstructuredContent()

	storedOidcConfig := &v32.OIDCConfig{}
	mapstructure.Decode(storedOidcConfigMap, storedOidcConfig)

	metadataMap, ok := storedOidcConfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("[generic oidc]: failed to retrieve OIDCConfig metadata, cannot read k8s Unstructured data")
	}

	objectMeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, objectMeta)
	storedOidcConfig.ObjectMeta = *objectMeta

	if storedOidcConfig.PrivateKey != "" {
		value, err := common.ReadFromSecret(o.secrets, storedOidcConfig.PrivateKey, strings.ToLower(client.OIDCConfigFieldPrivateKey))
		if err != nil {
			return nil, err
		}
		storedOidcConfig.PrivateKey = value
	}
	return storedOidcConfig, nil
}

func (o *oidcProvider) isThisUserMe(me v3.Principal, other v3.Principal) bool {
	if me.ObjectMeta.Name == other.ObjectMeta.Name && me.LoginName == other.LoginName && me.PrincipalType == other.PrincipalType {
		return true
	}
	return false
}
