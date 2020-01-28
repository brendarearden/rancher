package utils

import (
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "works http",
			url:     "http://example.com/abc?d=ef",
			wantErr: false,
		},
		{
			name:    "works git",
			url:     "git://example.com/abc?d=ef",
			wantErr: false,
		},
		{
			name: "cntrl error",
			url: "http://example.com/	abc",
			wantErr: true,
		},
		{
			name:    "urlencode error",
			url:     "git://example.com%0D/abc",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURL(tt.url); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}


func TestFormatNameAndVersionLabel(t *testing.T){
	type testcase struct {
		caseName       string
		string    string
	}
	type negativeCase struct {
		caseName       string
		string    string
		errorString string
		numErrors int
	}
	positiveTestCases := []testcase{
		{
			caseName: "default",
			string: "chartmuseum-v1.2.3",
		},
		{
			caseName: "ending with hyphen",
			string: "chartmuseum-v1.2.3-dirty-",
		},
		{
			caseName: "needs to be truncated",
			string: "chartmuseumthisisneedadfdingsdffaoadfasdfasdfasdfmfsomthesortoftruncating-1.0.0-beta+exp.sha.5114f85",
		},
		{
			caseName: "truncation ends with hyphen",
			string: "chartmuseumthisisneedingsdffaomfsomthffsortoftruncating-v1.2.3-dirty-",
		},
	}
	negativeTestCases := []negativeCase{
		{
			caseName: "default with with invalid character",
			string: "chart&museum-v1.2.3",
			errorString: "a DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character",
			numErrors: 1,
		},
		{
			caseName: "ending with hyphen with invalid character",
			string: "chart^&museum-1.0.0-beta+exp.sha.5114f85",
			errorString: "a DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character",
			numErrors: 1,
		},
		{
			caseName: "needs to be truncated with invalid character",
			string: "chartmuseumthisisnee/dadfdingsdffaoadfasdfasdfasdfmfsomthesortoftruncating-v1.2.3-dirty-",
			errorString: "a DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character",
			numErrors: 1,
		},
		{
			caseName: "truncation ends with underscore but chart starts with number",
			string: "1chartmuseumthisndeedigs?dffaomfffsfsortotruncating-1.0.0-beta+exp.sha.5114f85",
			errorString: "a DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character",
			numErrors: 1,
		},
	}

	for _, p := range positiveTestCases {

		assert.Empty(t, validation.IsDNS1123Subdomain(FormatNameAndVersionLabel(p.string)))
	}
	for _, n := range negativeTestCases {
		results := FormatNameAndVersionLabel(n.string)
		println(results)
		assert.Equal(t, n.numErrors, len(validation.IsDNS1123Subdomain(results)))
		assert.Contains(t, validation.IsDNS1123Subdomain(results)[0], n.errorString)
	}
}
