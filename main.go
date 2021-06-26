package main

import (
	"log"

	"git.neveris.one/gryffyn/genca/config"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	cin := config.Cfg{
		Outfile: "config.yml",
		Config:  &config.Config{},
	}
	err := cin.Get()
	if err != nil {
		log.Fatalln(err)
	}
	spew.Dump(&cin.Config)
}
