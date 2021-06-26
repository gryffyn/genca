package config

import (
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

type Dn struct {
	Organization  string `yaml:"organization"`
	Country       string `yaml:"country"`
	Province      string `yaml:"province"`
	Locality      string `yaml:"locality"`
	StreetAddress string `yaml:"streetAddress"`
	PostalCode    string `yaml:"postalCode"`
	CommonName    string `yaml:"commonName"`
}

type Config struct {
	Ca   Ca     `yaml:"ca"`
	Cert []Cert `yaml:"cert"`
}

type Ca struct {
	ExpiryTime int `yaml:"expiryTime"`
	Dn         Dn  `yaml:"dn"`
}

type Cert struct {
	Name       string   `yaml:"name"`
	ExpiryTime int      `yaml:"expiryTime"`
	Dns        []string `yaml:"dns"`
	Ip         []string `yaml:"ip"`
	Dn         Dn       `yaml:"dn"`
}

type Cfg struct {
	Outfile string
	Config  *Config
}

func ofile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, os.FileMode.Perm(0644))
}

func (c *Cfg) Write() error {
	confm, _ := yaml.Marshal(&c.Config)
	return ofile(c.Outfile, confm)
}

func (c *Cfg) Get() error {
	in, err := os.ReadFile(c.Outfile)
	err = yaml.Unmarshal(in, c.Config)
	return err
}
