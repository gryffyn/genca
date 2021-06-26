package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"time"

	"git.neveris.one/gryffyn/genca/config"
)

type CertAuth struct {
	ExpiryTime int
	CAName     pkix.Name
	CertReq    *x509.Certificate
	Key        *rsa.PrivateKey
	PemCert    string
	PemKey     string
}

func CAFromConfig(cfg config.Config) CertAuth {
	ca := CertAuth{
		ExpiryTime: cfg.Ca.ExpiryTime,
		CAName: pkix.Name{
			Country: []string{
				cfg.Ca.Dn.Country,
			},
			Organization: []string{
				cfg.Ca.Dn.Organization,
			},
			Locality: []string{
				cfg.Ca.Dn.Locality,
			},
			Province: []string{
				cfg.Ca.Dn.Province,
			},
			StreetAddress: []string{
				cfg.Ca.Dn.StreetAddress,
			},
			PostalCode: []string{
				cfg.Ca.Dn.PostalCode,
			},
			CommonName: cfg.Ca.Dn.CommonName,
		},
	}
	return ca
}

func (ca *CertAuth) genCertReq() {
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               ca.CAName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(ca.ExpiryTime, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	ca.CertReq = cert
}

func (ca *CertAuth) genKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	ca.Key = key
	ca.PemKey = pemEncodeKey(key)
	return nil
}

func (ca *CertAuth) genCert() error {
	cert, err := x509.CreateCertificate(rand.Reader, ca.CertReq, ca.CertReq, &ca.Key.PublicKey, ca.Key)
	if err != nil {
		return err
	}
	ca.PemCert = pemEncodeCert(cert)
	return nil
}

func (ca *CertAuth) writeKey(path string) error {
	var fullpath string
	if strings.HasSuffix(path, "/") {
		fullpath = path + "ca" + "/"
	} else {
		fullpath = path + "/" + "ca" + "/"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + "ca.key")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.WriteString(ca.PemKey)
	if err != nil {
		return err
	}
	return nil
}

func (ca *CertAuth) writeCert(path string) error {
	var fullpath string
	if strings.HasSuffix(path, "/") {
		fullpath = path + "ca" + "/"
	} else {
		fullpath = path + "/" + "ca" + "/"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + "ca.crt")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.WriteString(ca.PemCert)
	if err != nil {
		return err
	}
	return nil
}

func (ca *CertAuth) GenCert() error {
	ca.genCertReq()
	err := ca.genKey()
	err = ca.genCert()
	if err != nil {
		return err
	}
	return nil
}

func (ca *CertAuth) Write(path string) error {
	err := ca.writeCert(path)
	err = ca.writeKey(path)
	if err != nil {
		return err
	}
	return nil
}
