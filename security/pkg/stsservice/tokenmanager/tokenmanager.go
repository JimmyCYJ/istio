// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokenmanager

import (
	"errors"
	"fmt"
	"sync"

	"istio.io/istio/pkg/bootstrap/platform"
	"istio.io/istio/security/pkg/stsservice"
	"istio.io/istio/security/pkg/stsservice/tokenmanager/google"
)

const (
	// GoogleTokenExchange is the name of the google token exchange service.
	GoogleTokenExchange = "GoogleTokenExchange"
)

// Plugin provides common interfaces for specific token exchange services.
type Plugin interface {
	ExchangeToken(parameters stsservice.StsRequestParameters) ([]byte, error)
	DumpPluginStatus() ([]byte, error)
}

type TokenManager struct {
	plugin Plugin
}

type Config struct {
	TrustDomain string
}

// GCPProjectInfo stores GCP project information, including project number,
// project ID, cluster location, cluster name
type GCPProjectInfo struct {
	number          string
	ID              string
	cluster         string
	clusterLocation string
}

var (
	// Singleton object of GCP project information
	gcpInfo *GCPProjectInfo
	once    sync.Once
)

// GetGCPProjectInfo fetches GCP information from GCP metadata server and returns the information.
// This method is thread safe.
func GetGCPProjectInfo() *GCPProjectInfo {
	once.Do(func() {
		gcpInfo = &GCPProjectInfo{}
		if platform.IsGCP() {
			md := platform.NewGCP().Metadata()
			if projectNum, found := md[platform.GCPProjectNumber]; found {
				gcpInfo.number = projectNum
			}
			if projectID, found := md[platform.GCPProject]; found {
				gcpInfo.ID = projectID
			}
			if clusterName, found := md[platform.GCPCluster]; found {
				gcpInfo.cluster = clusterName
			}
			if clusterLocation, found := md[platform.GCPLocation]; found {
				gcpInfo.clusterLocation = clusterLocation
			}
		}
	})
	return gcpInfo
}

// CreateTokenManager creates a token manager with specified type and returns
// that token manager
func CreateTokenManager(tokenManagerType string, config Config) stsservice.TokenManager {
	tm := &TokenManager{
		plugin: nil,
	}
	switch tokenManagerType {
	case GoogleTokenExchange:
		if projectInfo := GetGCPProjectInfo(); len(projectInfo.number) > 0 {
			gkeClusterURL := fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
				projectInfo.ID, projectInfo.clusterLocation, projectInfo.cluster)
			if p, err := google.CreateTokenManagerPlugin(config.TrustDomain, projectInfo.number, gkeClusterURL, true); err == nil {
				tm.plugin = p
			}
		}
	}
	return tm
}

func (tm *TokenManager) GenerateToken(parameters stsservice.StsRequestParameters) ([]byte, error) {
	if tm.plugin != nil {
		return tm.plugin.ExchangeToken(parameters)
	}
	return nil, errors.New("no plugin is found")
}

func (tm *TokenManager) DumpTokenStatus() ([]byte, error) {
	if tm.plugin != nil {
		return tm.plugin.DumpPluginStatus()
	}
	return nil, errors.New("no plugin is found")
}

// SetPlugin sets token exchange plugin for testing purposes only.
func (tm *TokenManager) SetPlugin(p Plugin) {
	tm.plugin = p
}
