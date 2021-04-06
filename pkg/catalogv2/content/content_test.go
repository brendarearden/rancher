package content

import (
	"reflect"
	"testing"
	"time"

	"github.com/rancher/rancher/pkg/settings"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/repo"
)

func TestFilterReleases(t *testing.T) {
	tests := []struct {
		testName               string
		chartVersionAnnotation string
		rancherVersion         string
		expectedPass           bool
	}{
		{
			"rancher version in range comparison with `>= <`style comparison",
			">= 2.5.0-alpha <2.6.0",
			"2.5.0-alpha",
			true,
		},
		{
			"rancher version in range comparison with `> <`style comparison",
			">2.5.0 <2.6.0",
			"v2.5.7",
			true,
		},
		{
			"rancher version in range comparison with `> <=`style comparison",
			">2.5.0-alpha <=2.6.0",
			"v2.6.0",
			true,
		},
		{
			"rancher version in range comparison with `>= <=`style comparison",
			">=2.5.0-alpha <=2.6.0",
			"v2.5.0",
			true,
		},
		{
			"rancher version in range comparison with `~` style comparison",
			"~2.5.x", //equivalent to >= 2.5.0, < 2.6.0
			"v2.5.7",
			true,
		},
		{
			"rancher version in range comparison with `<` style comparison",
			"<2.6.0",
			"v2.5.7",
			true,
		},
		{
			"rancher version in range comparison with `<=` style comparison",
			"<= 2.6.0",
			"v2.6.0-alpha",
			true,
		},
		{
			"rancher version in range comparison with `>=` style comparison",
			">= 2.4.3",
			"v3.0.0",
			true,
		},
		{
			"rancher version in range comparison with `>` style comparison",
			">2.4.3",
			"v2.4.4",
			true,
		},
		{
			"rancher version out of range comparison with `>= <`style comparison",
			">= 2.5.0-alpha <2.6.0",
			"v2.4.9",
			false,
		},
		{
			"rancher version out of range comparison with `> <`style comparison",
			">2.5.0 <2.6.0",
			"v2.6.1",
			false,
		},
		{
			"rancher version out of range comparison with `> <=`style comparison",
			"> 2.5.0-alpha <=2.6.0",
			"v2.6.0-alpha",
			false,
		},
		{
			"rancher version out of range comparison with `>= <=`style comparison",
			">=2.5.0-alpha <=2.6.0",
			"v2.4.2",
			false,
		},
		{
			"rancher version out of range comparison with `~` style comparison",
			"~2.5.x", //equivalent to >= 2.5.0, < 2.6.0
			"v2.6.0",
			false,
		},
		{
			"rancher version out of range comparison with `<` style comparison",
			"<2.6.0", //equivalent to >= 2.6.0, < 2.7.0
			"v2.6.0",
			false,
		},
		{
			"rancher version out of range comparison with `<=` style comparison",
			"<=2.6.0", //equivalent to >= 2.6.0, < 2.7.0
			"v2.6.0-alpha",
			false,
		},
		{
			"rancher version out of range comparison with `>=` style comparison",
			">= 2.4.3", //equivalent to >= 2.6.0, < 2.7.0
			"v2.4.2",
			false,
		},
		{
			"rancher version out of range comparison with `>` style comparison",
			">2.4.3", //equivalent to >= 2.6.0, < 2.7.0
			"v2.4.3",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			indexFile := repo.IndexFile{
				Entries: map[string]repo.ChartVersions{
					"test-chart": {
						{
							Metadata: &chart.Metadata{
								Name:    "test-chart",
								Version: "1.0.0",
								Annotations: map[string]string{
									"catalog.cattle.io/rancher-version": tt.chartVersionAnnotation,
								},
							},
							URLs:    nil,
							Created: time.Time{},
							Removed: false,
							Digest:  "",
						},
					},
				},
			}
			filteredIndexFile := repo.IndexFile{
				Entries: map[string]repo.ChartVersions{
					"test-chart": {
						{
							Metadata: &chart.Metadata{
								Name:    "test-chart",
								Version: "1.0.0",
								Annotations: map[string]string{
									"catalog.cattle.io/rancher-version": tt.chartVersionAnnotation,
								},
							},
							URLs:    nil,
							Created: time.Time{},
							Removed: false,
							Digest:  "",
						},
					},
				},
			}
			contentManager := Manager{}
			settings.ServerVersion.Set(tt.rancherVersion)
			contentManager.filterReleases(&filteredIndexFile, nil)
			result := reflect.DeepEqual(indexFile, filteredIndexFile)
			assert.Equal(t, tt.expectedPass, result)
			if result != tt.expectedPass {
				t.Logf("Expected %v, got %v for %s with rancher version %s", tt.expectedPass, result, tt.chartVersionAnnotation, tt.rancherVersion)
			}
		})
	}
}
