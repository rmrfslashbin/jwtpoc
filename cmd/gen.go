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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/rmrfslashbin/jwtpoc/pkg/jwtpoc"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a JWT",
	Long:  `Generate a JWT from the provided secret and userid`,
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
		if err := generateJWT(); err != nil {
			log.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("error")
		}
	},
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.PersistentFlags().String("userid", "", "userid")
	viper.BindPFlag("userid", genCmd.PersistentFlags().Lookup("userid"))
}

func generateJWT() error {
	secret := viper.GetString("secret")
	if secret == "" {
		return fmt.Errorf("gen.go: getJWT: secret is required")
	}

	userid := viper.GetString("userid")
	if userid == "" {
		return fmt.Errorf("gen.go: getJWT: userid is required")
	}

	log.WithFields(logrus.Fields{
		"secret": secret,
	}).Info("genJWT")

	x, err := jwtpoc.New(jwtpoc.SetLog(log), jwtpoc.SetSecret(secret))
	if err != nil {
		return err
	}

	if token, err := x.Create(userid); err != nil {
		return err
	} else {
		log.WithFields(logrus.Fields{
			"token": token,
		}).Info("token generated")
	}

	return nil
}
