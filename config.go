package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

func exitWithError(message string) {
	fmt.Fprintf(os.Stderr, "%s\n\n", message)
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func loadEnvYAML() {
	// yaml configuration is expected in current working directory
	myWd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	envCfg := path.Join(myWd, yamlCfgFileName)
	_, err = os.Stat(envCfg)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return
	}
	cfgContents, err := ioutil.ReadFile(envCfg)
	if err != nil {
		log.Fatalf("error reading %s: %v ", yamlCfgFileName, err)
	}
	cfg := map[string]string{}
	err = yaml.Unmarshal(cfgContents, cfg)
	if err != nil {
		log.Fatalf("yaml unmarshal error: %v", err)
	}
	if val, found := cfg[domainYamlKey]; found {
		auth0Domain = val
	}
	if val, found := cfg[audienceYamlKey]; found {
		auth0Audience = val
	}
}

func parseArgs() {
	var argAudience, argDomain string
	flag.StringVar(&argAudience, "a",
		os.Getenv("AUTH0_AUDIENCE"), "Auth0 API identifier, as audience")
	flag.StringVar(&argDomain, "d",
		os.Getenv("AUTH0_DOMAIN"), "Auth0 API tenant domain")
	flag.Parse()
	if argAudience != "" {
		auth0Audience = argAudience
	}
	if argDomain != "" {
		auth0Domain = argDomain
	}
}

func initConfig() {
	loadEnvYAML()
	parseArgs()
	if auth0Audience == "" {
		exitWithError("Auth0 API identifier (as audience) missing")
	}
	if auth0Domain == "" {
		exitWithError("Auth0 API tenant domain missing")
	}
}
