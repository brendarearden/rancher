package client

const (
	OIDCApplyInputType            = "oidcApplyInput"
	OIDCApplyInputFieldCode       = "code"
	OIDCApplyInputFieldEnabled    = "enabled"
	OIDCApplyInputFieldOidcConfig = "oidcConfig"
)

type OIDCApplyInput struct {
	Code       string      `json:"code,omitempty" yaml:"code,omitempty"`
	Enabled    bool        `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	OidcConfig *OIDCConfig `json:"oidcConfig,omitempty" yaml:"oidcConfig,omitempty"`
}
