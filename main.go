package main

import (
	"fmt"
	"log"
	"os"

	"git.neveris.one/gryffyn/genca/cert"
	"git.neveris.one/gryffyn/genca/config"
)

func main() {
	fmt.Println("Loading config...")
	cfg := config.Cfg{
		Outfile: "config.yml",
		Config:  &config.Config{},
	}
	err := cfg.Get()
	if err != nil {
		log.Fatalln(err)
	}

	cwd, err := os.Getwd()

	ca := cert.CAFromConfig(*cfg.Config)
	certs := cert.CertsFromConfig(*cfg.Config)

	fmt.Println("Generating CA...")
	err = ca.GenCert()
	fmt.Println("Writing CA...")
	err = ca.Write(cwd + "/ssl")

	for _, cc := range certs {
		fmt.Println("Generating cert '" + cc.Name + "'...")
		err = cc.GenCert(&ca)
		fmt.Println("Writing cert '" + cc.Name + "'...")
		err = cc.Write(cwd + "/ssl")
	}
}
