# genca
[![Build Status](https://ci.neveris.one/api/badges/gryffyn/genca/status.svg)](https://ci.neveris.one/gryffyn/genca)  

Tool for generating a self-signed CA and CA-signed TLS certificates, using yaml for configuration.

## Building / Installing

```
git clone https://git.neveris.one/gryffyn/genca
cd genca
go build
```

or 

`go get git.neveris.one/gryffyn/genca`

## Usage

Copy `config.yml.dist` to `config.yml` and edit, then run `genca`.

## Limitations

For now, this is a single-pass, meaning you can't generate more client certs with the same CA cert. That functionality will come eventually.

## License
Licensed under the MIT license.
See `LICENSE` for details.