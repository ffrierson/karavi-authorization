// Copyright © 2021 Dell Inc., or its subsidiaries. All Rights Reserved.
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

package cmd

import (
	"context"
	"errors"
	"karavi-authorization/pb"
	"strings"

	"github.com/spf13/cobra"
)

// tenantCreateCmd represents the tenant command
var tenantCreateCmd = &cobra.Command{
	Use:              "create",
	TraverseChildren: true,
	Short:            "Create a tenant resource within Karavi",
	Long:             `Creates a tenant resource within Karavi`,
	Run: func(cmd *cobra.Command, args []string) {
		addr, err := cmd.Flags().GetString("addr")
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), err)
		}

		tenantClient, conn, err := CreateTenantServiceClient(addr)
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), err)
		}
		defer conn.Close()

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), err)
		}
		if strings.TrimSpace(name) == "" {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), errors.New("empty name not allowed"))
		}

		_, err = tenantClient.CreateTenant(context.Background(), &pb.CreateTenantRequest{
			Tenant: &pb.Tenant{
				Name: name,
			},
		})
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), err)
		}
	},
}

func init() {
	tenantCmd.AddCommand(tenantCreateCmd)

	tenantCreateCmd.Flags().StringP("name", "n", "", "Tenant name")
}