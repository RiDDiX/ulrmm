// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"flag"
	"fmt"
	"runtime/debug"

	"git.riddix.de/RiDDiX/ulrmm/natsapi"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev"
	log     = logrus.New()
)

func main() {
	ver := flag.Bool("version", false, "Prints version")
	cfg := flag.String("config", "", "Path to config file")
	logLevel := flag.String("log", "INFO", "The log level")
	flag.Parse()

	if *ver {
		fmt.Println(version)
		bi, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println(bi.String())
		}
		return
	}

	setupLogging(logLevel)

	api.Svc(log, *cfg)
}

func setupLogging(level *string) {
	ll, err := logrus.ParseLevel(*level)
	if err != nil {
		ll = logrus.InfoLevel
	}
	log.SetLevel(ll)
}
