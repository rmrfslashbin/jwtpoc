/*
Copyright © 2022 Robert Sigler <sigler@improvisedscience.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/rmrfslashbin/jwtpoc/pkg/jwtpoc"
)

// valCmd represents the val command
var valCmd = &cobra.Command{
	Use:   "val",
	Short: "Validate a JWT",
	Long:  `Validate a JWT with the provided secret.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Catch errors
		var err error
		defer func() {
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": err,
				}).Fatal("main crashed")
			}
		}()
		if err := validateJWT(); err != nil {
			log.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("error")
		}
	},
}

func init() {
	rootCmd.AddCommand(valCmd)

	valCmd.PersistentFlags().String("token", "", "token")
	viper.BindPFlag("token", valCmd.PersistentFlags().Lookup("token"))

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// valCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// valCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func validateJWT() error {
	secret := viper.GetString("secret")
	if secret == "" {
		return fmt.Errorf("val.go: validateJWT: secret is required")
	}

	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("val.go: validateJWT: token is required")
	}

	x, err := jwtpoc.New(jwtpoc.SetLog(log), jwtpoc.SetSecret(secret))
	if err != nil {
		return err
	}
	if claims, err := x.Validate(token); err != nil {
		return err
	} else {
		log.Info("Token is valid")
		spew.Dump(claims)
	}

	return nil
}
