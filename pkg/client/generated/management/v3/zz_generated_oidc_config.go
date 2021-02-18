package client

const (
	OIDCConfigType                     = "oidcConfig"
	OIDCConfigFieldAccessMode          = "accessMode"
	OIDCConfigFieldAllowedPrincipalIDs = "allowedPrincipalIds"
	OIDCConfigFieldAnnotations         = "annotations"
	OIDCConfigFieldAuthEndpoint        = "authEndpoint"
	OIDCConfigFieldCertificate         = "certificate"
	OIDCConfigFieldClientID            = "clientId"
	OIDCConfigFieldClientSecret        = "clientSecret"
	OIDCConfigFieldCreated             = "created"
	OIDCConfigFieldCreatorID           = "creatorId"
	OIDCConfigFieldEnabled             = "enabled"
	OIDCConfigFieldGrantType           = "grantType"
	OIDCConfigFieldLabels              = "labels"
	OIDCConfigFieldName                = "name"
	OIDCConfigFieldOwnerReferences     = "ownerReferences"
	OIDCConfigFieldPrivateKey          = "spKey"
	OIDCConfigFieldRancherUrl          = "rancherUrl"
	OIDCConfigFieldRemoved             = "removed"
	OIDCConfigFieldResponseType        = "responseType"
	OIDCConfigFieldScopes              = "scope"
	OIDCConfigFieldTokenEndpoint       = "tokenEndpoint"
	OIDCConfigFieldType                = "type"
	OIDCConfigFieldUUID                = "uuid"
	OIDCConfigFieldUserInfoEndpoint    = "userInfoEndpoint"
)

type OIDCConfig struct {
	AccessMode          string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AllowedPrincipalIDs []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations         map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	AuthEndpoint        string            `json:"authEndpoint,omitempty" yaml:"authEndpoint,omitempty"`
	Certificate         string            `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	ClientID            string            `json:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret        string            `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	Created             string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID           string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Enabled             bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	GrantType           string            `json:"grantType,omitempty" yaml:"grantType,omitempty"`
	Labels              map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Name                string            `json:"name,omitempty" yaml:"name,omitempty"`
	OwnerReferences     []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	PrivateKey          string            `json:"spKey,omitempty" yaml:"spKey,omitempty"`
	RancherUrl          string            `json:"rancherUrl,omitempty" yaml:"rancherUrl,omitempty"`
	Removed             string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	ResponseType        string            `json:"responseType,omitempty" yaml:"responseType,omitempty"`
	Scopes              string            `json:"scope,omitempty" yaml:"scope,omitempty"`
	TokenEndpoint       string            `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
	Type                string            `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	UserInfoEndpoint    string            `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
}
