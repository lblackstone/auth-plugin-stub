// broker consists of the entry point for the authz broker
package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/lblackstone/auth-plugin-stub/authz"
	"github.com/lblackstone/auth-plugin-stub/core"
)

const (
	debugFlag       = "debug"
	authorizerFlag  = "authz-handler"
	auditorFlag     = "auditor"
	auditorHookFlag = "auditor-hook"
	policyFileFlag  = "policy-file"
)

const (
	authorizerBasic = "basic"
)

const (
	auditorBasic = "basic"
)

func main() {

	app := cli.NewApp()
	app.Name = "Docker Auth Plugin Stub"
	app.Usage = "Authorization plugin for docker"
	app.Version = "0.1"

	app.Action = func(c *cli.Context) {

		initLogger(c.GlobalBool(debugFlag))

		var auditor core.Auditor
		var authZHandler core.Authorizer

		authZHandler = authz.NewBasicAuthZAuthorizer(
			&authz.BasicAuthorizerSettings{PolicyPath: c.GlobalString(policyFileFlag)})

		auditor = authz.NewBasicAuditor(
			&authz.BasicAuditorSettings{LogHook: c.GlobalString(auditorHookFlag)})

		srv := core.NewAuthZSrv(authZHandler, auditor)

		if err := srv.Start(); err != nil {
			panic(err)
		}
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   debugFlag,
			Usage:  "Enable debug mode",
			EnvVar: "DEBUG",
		},

		cli.StringFlag{
			Name:   auditorHookFlag,
			Value:  authz.AuditHookStdout,
			EnvVar: "AUDITOR-HOOK",
			Usage:  "Defines the authz auditor hook type (log engine)",
		},
	}

	app.Run(os.Args)
}

// initLogger initialize the logger based on the log level
func initLogger(debug bool) {

	logrus.SetFormatter(&logrus.TextFormatter{})

	// Output to stderr instead of stdout, could also be a file.
	logrus.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	logrus.SetLevel(logrus.DebugLevel)
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}
