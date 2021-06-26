package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"git.neveris.one/gryffyn/genca/config"
)

type CertClient struct {
	Name       string
	ExpiryTime int
	CAName     pkix.Name
	IP         []string
	DNS        []string
	Key        *rsa.PrivateKey
	CertReq    *x509.Certificate
	PemCert    string
	PemKey     string
}

func CertsFromConfig(cfg config.Config) []CertClient {
	var certs []CertClient
	for _, cert := range cfg.Cert {
		client := CertClient{
			Name:       cert.Name,
			ExpiryTime: cert.ExpiryTime,
			CAName: pkix.Name{
				Country: []string{
					cert.Dn.Country,
				},
				Organization: []string{
					cert.Dn.Organization,
				},
				Locality: []string{
					cert.Dn.Locality,
				},
				Province: []string{
					cert.Dn.Province,
				},
				StreetAddress: []string{
					cert.Dn.StreetAddress,
				},
				PostalCode: []string{
					cert.Dn.PostalCode,
				},
				CommonName: cert.Dn.CommonName,
			},
			IP:  cert.Ip,
			DNS: cert.Dns,
		}
		certs = append(certs, client)
	}
	return certs
}

func pemEncodeCert(cert []byte) string {
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return caPEM.String()
}

func pemEncodeKey(key *rsa.PrivateKey) string {
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return caPrivKeyPEM.String()
}

func (cc *CertClient) genCertReq() {
	var ips []net.IP
	for _, v := range cc.IP {
		ips = append(ips, net.ParseIP(v))
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      cc.CAName,
		DNSNames:     cc.DNS,
		IPAddresses:  ips,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(cc.ExpiryTime, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	cc.CertReq = cert
}

func (cc *CertClient) genKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	cc.Key = key
	cc.PemKey = pemEncodeKey(key)
	return nil
}

func (cc *CertClient) genCert(ca *CertAuth) error {
	cert, err := x509.CreateCertificate(rand.Reader, cc.CertReq, ca.CertReq, &cc.Key.PublicKey, ca.Key)
	if err != nil {
		return err
	}
	cc.PemCert = pemEncodeCert(cert)
	return nil
}

func (cc *CertClient) writeCert(path string) error {
	var fullpath string
	if strings.HasSuffix(path, "/") {
		fullpath = path + cc.Name + "/"
	} else {
		fullpath = path + "/" + cc.Name + "/"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + cc.Name + ".crt")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.WriteString(cc.PemCert)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CertClient) writeKey(path string) error {
	var fullpath string
	if strings.HasSuffix(path, "/") {
		fullpath = path + cc.Name + "/"
	} else {
		fullpath = path + "/" + cc.Name + "/"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + cc.Name + ".key")
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.WriteString(cc.PemKey)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CertClient) GenCert(ca *CertAuth) error {
	cc.genCertReq()
	err := cc.genKey()
	err = cc.genCert(ca)
	if err != nil {
		return err
	}
	return nil
}

func (cc *CertClient) Write(path string) error {
	err := cc.writeCert(path)
	err = cc.writeKey(path)
	if err != nil {
		return err
	}
	return nil
}
