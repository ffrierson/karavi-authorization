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
	"os"

	"github.com/spf13/cobra"
)

// NewGenerateCmd creates a new generate command
func NewGenerateCmd() *cobra.Command {
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate resources for use with Karavi",
		Long:  `Generates resources for use with Karavi`,
		Run: func(cmd *cobra.Command, _ []string) {
			err := cmd.Usage()
			if err != nil {
				reportErrorAndExit(JSONOutput, os.Stderr, err)
			}
			os.Exit(1)
		},
	}

	generateCmd.PersistentFlags().StringP("admin-token", "f", "", "Path to admin token file; required")
	generateCmd.PersistentFlags().String("addr", "", "Address of the CSM Authorization Proxy Server; required")
	generateCmd.PersistentFlags().Bool("insecure", false, "Skip certificate validation of the CSM Authorization Proxy Server")

	err := generateCmd.MarkPersistentFlagRequired("admin-token")
	if err != nil {
		reportErrorAndExit(JSONOutput, generateCmd.ErrOrStderr(), err)
	}

	err = generateCmd.MarkPersistentFlagRequired("addr")
	if err != nil {
		reportErrorAndExit(JSONOutput, generateCmd.ErrOrStderr(), err)
	}

	generateCmd.AddCommand(NewGenerateTokenCmd())
	return generateCmd
}
