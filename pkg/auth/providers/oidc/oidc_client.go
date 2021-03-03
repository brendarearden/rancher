package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
)

type UserInfo struct {
	Subject       string   `json:"sub"`
	Name          string   `json:"name"`
	Profile       string   `json:"profile"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
	claims        []byte
}

type IDToken struct {
	Issuer   string    `json:"iss"`
	Subject  string    `json:"sub"`
	Audience []string  `json:"aud"`
	Expiry   time.Time `json:"exp"`
	IssuedAt time.Time `json:"iat"`
	Nonce    string    `json:"nonce"`
}

type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"exp"`
}

type WellKnownConfig struct {
	Issuer                 string   `json:"issuer"`
	AuthEndpoint           string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JwksURI                string   `json:"jwks_uri"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ClaimsSupported        []string `json:"claims_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

//Client implements a httpclient for oidc auth
type Client struct {
	httpClient *http.Client
}

func (o *Client) getUserInfo(authToken string, config *v32.OIDCConfig, pool *x509.CertPool) (*UserInfo, error) {
	if config.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("[generic oidc]: user info enpoint was not provided")
	}
	req, err := http.NewRequest("GET", config.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("[generic oidc]: issue creating GET request: %v", err)
	}
	req.Header.Add("Authorization", "Bearer "+authToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	body, err := o.doRequest(req, config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("[generic oidc]: failed to decode userinfo: %v", err)
	}
	return &UserInfo{
		Subject:       userInfo.Subject,
		Name:          userInfo.Name,
		Profile:       userInfo.Profile,
		Email:         userInfo.Email,
		EmailVerified: bool(userInfo.EmailVerified),
		Groups:        userInfo.Groups,
		claims:        body,
	}, nil
}

//Authentication Request to Authorization Server - Exchanges Code for Auth Token
func (o *Client) getAccessTokens(code string, config *v32.OIDCConfig, pool *x509.CertPool) (*Tokens, error) {
	form := url.Values{}
	form.Add("client_id", config.ClientID)
	form.Add("client_secret", config.ClientSecret)
	form.Add("response_type", config.ResponseType)
	form.Add("grant_type", config.GrantType)
	form.Add("code", code)
	form.Add("redirect_uri", config.RancherURL)

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		logrus.Error(err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	body, err := o.doRequest(req, config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}

	var accessTokens Tokens
	if err := json.Unmarshal(body, &accessTokens); err != nil {
		return nil, fmt.Errorf("[generic oidc] unable to decode ")
	}
	return &accessTokens, nil
}

func (o *Client) getWellKnownConfig(config *v32.OIDCConfig, pool *x509.CertPool) (*WellKnownConfig, error) {
	var wkConfig *WellKnownConfig

	if config.Issuer == "" {
		return wkConfig, fmt.Errorf("[generic oidc]: issuer was not provided")
	}
	wkEndPoint := strings.TrimSuffix(config.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wkEndPoint, nil)
	if err != nil {
		return wkConfig, fmt.Errorf("[generic oidc]: issue creating GET request: %v", err)
	}

	body, err := o.doRequest(req, config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &wkConfig); err != nil {
		return wkConfig, fmt.Errorf("[generic oidc]: failed to decode well-known config: %v", err)
	}
	return &WellKnownConfig{
		Issuer:                 wkConfig.Issuer,
		AuthEndpoint:           wkConfig.AuthEndpoint,
		TokenEndpoint:          wkConfig.TokenEndpoint,
		UserInfoEndpoint:       wkConfig.UserInfoEndpoint,
		JwksURI:                wkConfig.JwksURI,
		ResponseTypesSupported: wkConfig.ResponseTypesSupported,
		ClaimsSupported:        wkConfig.ClaimsSupported,
		ScopesSupported:        wkConfig.ScopesSupported,
	}, nil
}

func (o *Client) doRequest(req *http.Request, certificate, privateKey string) ([]byte, error) {
	var resp *http.Response
	var err error

	if certificate != "" && privateKey != "" {
		cert, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("[generic oidc] unable to parse certificate and private key: %v", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(certificate))

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		o.httpClient.Transport = transport
	}

	resp, err = o.httpClient.Do(req)

	if err != nil {
		logrus.Errorf("[generic oidc] received error from provider: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[generic oidc] unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[generic oidc] response Status: %s. Body: %s", resp.Status, body)
	}
	return body, nil
}
