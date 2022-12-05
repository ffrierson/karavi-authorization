// Copyright © 2022 Dell Inc., or its subsidiaries. All Rights Reserved.
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

package validate

import (
	"context"
	"fmt"
	"karavi-authorization/internal/types"
	"net/url"

	"github.com/dell/gounity"
	"github.com/sirupsen/logrus"
)

// GetUnityEndpoint returns the endpoint URL for a Unity system
var GetUnityEndpoint = func(system types.System) string {
	return system.Endpoint
}

// Unity validates unity storage parameters
func Unity(ctx context.Context, log *logrus.Entry, system types.System, systemID string) error {

	endpoint := GetUnityEndpoint(system)
	epURL, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint %s is invalid: %+v", epURL, err)
	}

	epURL.Scheme = "https"
	unityClient, err := gounity.NewClientWithArgs(epURL.String(), "", system.Insecure, false)
	if err != nil {
		return fmt.Errorf("failed to connect to unity %s: %+v", systemID, err)
	}

	_, err = unityClient.Authenticate(ctx, &gounity.ConfigConnect{
		Username: system.User,
		Password: system.Password,
	})

	if err != nil {
		return fmt.Errorf("unity authentication failed: %+v", err)
	}

	return nil
}
