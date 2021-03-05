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
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

var roleDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete role",
	Long:  `Delete role`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) == 0 {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), errors.New("role name is required"))
		}

		if len(args) > 1 {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), errors.New("expects single argument"))
		}

		roles, err := GetRoles()
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), fmt.Errorf("unable to get roles: %v", err))
		}

		roleName := args[0]

		if _, ok := roles[roleName]; !ok {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), fmt.Errorf("role %s does not exist", roleName))
		}

		delete(roles, roleName)

		err = modifyCommonConfigMap(roles)
		if err != nil {
			reportErrorAndExit(JSONOutput, cmd.ErrOrStderr(), fmt.Errorf("unable to delete role: %v", err))
		}
	},
}

func init() {
	roleCmd.AddCommand(roleDeleteCmd)
}