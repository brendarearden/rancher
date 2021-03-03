package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rancher/norman/api/handler"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	managementschema "github.com/rancher/rancher/pkg/schemas/management.cattle.io/v3"

	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providers/common"
)

func (o *oidcProvider) formatter(apiContext *types.APIContext, resource *types.RawResource) {
	common.AddCommonActions(apiContext, resource)
	resource.AddAction(apiContext, "configureTest")
	resource.AddAction(apiContext, "testAndApply")
}

func (o *oidcProvider) actionHandler(actionName string, action *types.Action, request *types.APIContext) error {
	handled, err := common.HandleCommonAction(actionName, action, request, Name, o.authConfigs)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	if actionName == "configureTest" {
		return o.configureTest(actionName, action, request)
	} else if actionName == "testAndApply" {
		return o.testAndApply(actionName, action, request)
	}

	return httperror.NewAPIError(httperror.ActionNotAvailable, "")
}

func (o *oidcProvider) configureTest(actionName string, action *types.Action, request *types.APIContext) error {
	//verify body has all required fields
	input, err := handler.ParseAndValidateActionBody(request, request.Schemas.Schema(&managementschema.Version,
		client.OIDCConfigType))
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"redirectUrl": o.getRedirectURL(input),
		"type":        "OIDCTestOutput",
	}
	request.WriteResponse(http.StatusOK, data)
	return nil
}
func (o *oidcProvider) testAndApply(actionName string, action *types.Action, request *types.APIContext) error {
	var oidcConfig v32.OIDCConfig
	oidcConfigApplyInput := &v32.OIDCApplyInput{}

	if err := json.NewDecoder(request.Request.Body).Decode(oidcConfigApplyInput); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("[generic oidc] testAndApply: Failed to parse body: %v", err))
	}

	oidcConfig = oidcConfigApplyInput.OidcConfig
	oidcLogin := &v32.OIDCLogin{
		Code: oidcConfigApplyInput.Code,
	}

	//call provider
	userPrincipal, groupPrincipals, providerToken, err := o.LoginUser(oidcLogin, &oidcConfig)
	if err != nil {
		if httperror.IsAPIError(err) {
			return err
		}
		return errors.Wrap(err, "[generic oidc]: server error while authenticating")
	}

	user, err := o.userMGR.SetPrincipalOnCurrentUser(request, userPrincipal)
	if err != nil {
		return err
	}

	err = o.saveOIDCConfig(&oidcConfig)
	if err != nil {
		return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Failed to save azure config: %v", err))
	}

	return o.tokenMGR.CreateTokenAndSetCookie(user.Name, userPrincipal, groupPrincipals, providerToken, 0, "Token via OIDC Configuration", request)
}
