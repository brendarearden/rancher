package oidc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type IDToken struct {
	Issuer          string    `json:"iss"`
	Subject         string    `json:"sub"`
	Audience        []string  `json:"aud"`
	Expiry          time.Time `json:"exp"`
	IssuedAt        time.Time `json:"iat"`
	Nonce           string    `json:"nonce"`
	AccessTokenHash string    `json:""`
	sigAlgorithm    string    `json:""`
	claims          []byte    `json:""`
}

type Tokens struct {
	AccessToken  oauth2.TokenSource `json:"access_token"`
	RefreshToken oauth2.TokenSource `json:"refresh_token"`
	Expiry       time.Time          `json:"exp"`
}

//Client implements a httpclient for oidc auth
type Client struct {
	httpClient *http.Client
}

func (o *Client) getLoginURL(config *v32.OIDCConfig) (string, error) {
	base, err := url.Parse(config.AuthEndpoint)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Add("client_id", config.ClientID)
	params.Add("response_type", "code")
	base.RawQuery = params.Encode()
	return base.String(), nil
}

func (o *Client) getUserInfo(authToken oauth2.TokenSource, config *v32.OIDCConfig) (*UserInfo, error) {
	if config.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("[generic oidc]: user info enpoint was not provided")
	}
	req, err := http.NewRequest("GET", config.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("[generic oidc]: issue creating GET request: %v", err)
	}

	token, err := authToken.Token()
	if err != nil {
		return nil, fmt.Errorf("[generic oidc]: issue getting access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("[generic oidc]: failed to decode userinfo: %v", err)
	}
	return &UserInfo{
		Subject:       userInfo.Subject,
		Profile:       userInfo.Profile,
		Email:         userInfo.Email,
		EmailVerified: bool(userInfo.EmailVerified),
	}, nil
}

//Authentication Request to Authorization Server - Exchanges Code for Auth Token
func (o *Client) getAccessTokens(code string, config *v32.OIDCConfig) (*Tokens, error) {
	form := url.Values{}
	form.Add("client_id", config.ClientID)
	form.Add("client_secret", config.ClientSecret)
	form.Add("response_type", "id_token")
	form.Add("authorization_code", code)
	form.Add("redirect_uri", config.RancherUrl)

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		logrus.Error(err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	resp, err := o.httpClient.Do(req)
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

	var accessTokens Tokens
	if err := json.Unmarshal(body, &accessTokens); err != nil {
		return nil, fmt.Errorf("[generic oidc] unable to decode ")
	}
	return &accessTokens, nil
}

func (o *Client) getIDToken(code string, config *v32.OIDCConfig) (*Tokens, error) {
	form := url.Values{}
	form.Add("client_id", config.ClientID)
	form.Add("client_secret", config.ClientSecret)
	form.Add("response_type", "id_token")
	form.Add("authorization_code", code)
	form.Add("redirect_uri", config.RancherUrl)

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		logrus.Error(err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	resp, err := o.httpClient.Do(req)
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

	var accessTokens Tokens
	if err := json.Unmarshal(body, &accessTokens); err != nil {
		return nil, fmt.Errorf("[generic oidc] unable to decode ")
	}
	return &accessTokens, nil
}
