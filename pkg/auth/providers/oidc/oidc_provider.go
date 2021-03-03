package oidc

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rancher/norman/types/convert"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
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
	Name      = "oidc"
	UserType  = "user"
	GroupType = "group"
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
	return o.LoginUser(login, nil)
}

func (o *oidcProvider) LoginUser(oauthLoginInfo *v32.OIDCLogin, config *v32.OIDCConfig) (v3.Principal, []v3.Principal, string, error) {
	var userPrincipal v3.Principal
	var groupPrincipal []v3.Principal
	var caPool *x509.CertPool
	var err error

	if config == nil {
		config, err = o.getOIDCConfig()
		if err != nil {
			return userPrincipal, nil, "", err
		}
	}
	logrus.Debugf("[generic oidc] loginuser: using code to get oauth token")
	code := oauthLoginInfo.Code

	logrus.Debugf("[generic oidc] loginuser: get well-known configuration")
	wk, err := o.oidcClient.getWellKnownConfig(config, caPool)
	if err != nil {
		return userPrincipal, groupPrincipal, "", err
	}
	logrus.Debugf("[generic oidc] loginuser: validate provider is supported")
	isSupportedProvider := isSupportedProvider(*wk, strings.Split(config.Scopes, ","))
	if !isSupportedProvider {
		return userPrincipal, groupPrincipal, "", errors.New("[generic oidc] Provider does not support required scopes and claims")
	}
	configUnsetEndpoints(*wk, config)
	logrus.Debugf("[generic oidc] loginuser: exchanging code for oauth tokens")
	oauthTokens, err := o.oidcClient.getAccessTokens(code, config, caPool)
	if err != nil {
		return userPrincipal, groupPrincipal, "", err
	}
	accessToken := oauthTokens.AccessToken
	userInfo, err := o.oidcClient.getUserInfo(accessToken, config, caPool)
	if err != nil {
		return userPrincipal, groupPrincipal, "", err
	}

	userPrincipal = o.userToPrincipal(userInfo)
	for _, group := range userInfo.Groups {
		groupPrincipal = append(groupPrincipal, o.groupToPrincipal(group))
	}
	logrus.Debugf("[generic oidc] loginuser: Checking user's access to Rancher")
	allowed, err := o.userMGR.CheckAccess(config.AccessMode, config.AllowedPrincipalIDs, userPrincipal.Name, groupPrincipal)
	if err != nil {
		return userPrincipal, groupPrincipal, "", err
	}
	if !allowed {
		return userPrincipal, groupPrincipal, "", httperror.NewAPIError(httperror.Unauthorized, "unauthorized")
	}
	return userPrincipal, groupPrincipal, accessToken, nil
}

func (o *oidcProvider) SearchPrincipals(searchValue, principalType string, token v3.Token) ([]v3.Principal, error) {
	var principals []v3.Principal
	if principalType == "" {
		principalType = UserType
	}

	p := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: "_" + principalType + "://" + searchValue},
		DisplayName:   searchValue,
		LoginName:     searchValue,
		PrincipalType: principalType,
		Provider:      Name,
	}

	principals = append(principals, p)
	return principals, nil
}

func (o *oidcProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	var p v3.Principal

	// parsing id to get the external id and type. Exaple oidc_<user|group>://<user sub | group name>
	var externalID string
	parts := strings.SplitN(principalID, ":", 2)
	if len(parts) != 2 {
		return p, errors.Errorf("invalid id %v", principalID)
	}
	externalID = strings.TrimPrefix(parts[1], "//")
	parts = strings.SplitN(parts[0], "_", 2)
	if len(parts) != 2 {
		return p, errors.Errorf("invalid id %v", principalID)
	}

	principalType := parts[1]
	if externalID == "" && principalType == "" {
		return p, fmt.Errorf("[generic oidc]: invalid id %v", principalID)
	}
	if principalType != UserType && principalType != GroupType {
		return p, fmt.Errorf("[generic oidc]: invalid principal type")
	}
	if principalID == UserType {
		p = v3.Principal{
			ObjectMeta:    metav1.ObjectMeta{Name: principalType + "://" + externalID},
			DisplayName:   externalID,
			LoginName:     externalID,
			PrincipalType: UserType,
			Provider:      Name,
		}
	} else {
		p = o.groupToPrincipal(externalID)
	}
	p = o.toPrincipalFromToken(principalType, p, &token)
	return p, nil
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
		"%s?client_id=%s&response_type=code&redirect_uri=%s",
		config["authEndpoint"],
		config["clientId"],
		config["rancherUrl"],
	)
}

func (o *oidcProvider) RefetchGroupPrincipals(principalID string, secret string) ([]v3.Principal, error) {
	return nil, errors.New("[generic oidc]: not implemented")
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

func (o *oidcProvider) userToPrincipal(userInfo *UserInfo) v3.Principal {
	displayName := userInfo.Name
	if displayName == "" {
		displayName = userInfo.Email
	}
	p := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: Name + "_" + UserType + "://" + userInfo.Subject},
		DisplayName:   displayName,
		LoginName:     userInfo.Email,
		Provider:      Name,
		PrincipalType: UserType,
		Me:            false,
	}
	return p
}

func (o *oidcProvider) groupToPrincipal(groupName string) v3.Principal {
	p := v3.Principal{
		ObjectMeta:    metav1.ObjectMeta{Name: Name + "_group://" + groupName},
		DisplayName:   groupName,
		Provider:      Name,
		PrincipalType: GroupType,
		Me:            false,
	}
	return p
}

func (o *oidcProvider) toPrincipalFromToken(principalType string, princ v3.Principal, token *v3.Token) v3.Principal {
	if principalType == UserType {
		princ.PrincipalType = UserType
		if token != nil {
			princ.Me = o.isThisUserMe(token.UserPrincipal, princ)
			if princ.Me {
				princ.LoginName = token.UserPrincipal.LoginName
				princ.DisplayName = token.UserPrincipal.DisplayName
			}
		}
	} else {
		princ.PrincipalType = GroupType
		if token != nil {
			princ.MemberOf = o.tokenMGR.IsMemberOf(*token, princ)
		}
	}
	return princ
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

	field := strings.ToLower(client.OIDCConfigFieldClientSecret)
	if err := common.CreateOrUpdateSecrets(o.secrets, convert.ToString(config.ClientSecret), field, strings.ToLower(config.Type)); err != nil {
		return err
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

	if storedOidcConfig.ClientSecret != "" {
		data, err := common.ReadFromSecretData(o.secrets, storedOidcConfig.ClientSecret)
		if err != nil {
			return nil, err
		}
		for _, v := range data {
			storedOidcConfig.ClientSecret = string(v)
		}
	}

	return storedOidcConfig, nil
}

func (o *oidcProvider) isThisUserMe(me v3.Principal, other v3.Principal) bool {
	if me.ObjectMeta.Name == other.ObjectMeta.Name && me.LoginName == other.LoginName && me.PrincipalType == other.PrincipalType {
		return true
	}
	return false
}

func configUnsetEndpoints(wkConfig WellKnownConfig, config *v32.OIDCConfig) *v32.OIDCConfig {
	if config.AuthEndpoint == "" {
		config.AuthEndpoint = wkConfig.AuthEndpoint
	}
	if config.UserInfoEndpoint == "" {
		config.UserInfoEndpoint = wkConfig.UserInfoEndpoint
	}
	if config.TokenEndpoint == "" {
		config.TokenEndpoint = wkConfig.TokenEndpoint
	}
	return config
}

func isSupportedProvider(wkConfig WellKnownConfig, reqScopes []string) bool {
	found := true
	validScopeClaim := append(wkConfig.ScopesSupported, wkConfig.ClaimsSupported...)
	for _, scope := range reqScopes {
		found = find(validScopeClaim, scope)
		if !found {
			return found
		}
	}
	return found
}

func find(values []string, val string) bool {
	for _, item := range values {
		if item == val {
			return true
		}
	}
	return false
}
