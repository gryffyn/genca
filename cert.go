package main

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
)

type CertAuth struct {
	ExpiryTime int
	CAName     pkix.Name
	CertReq    *x509.Certificate
	Key        *rsa.PrivateKey
	PemCert    string
	PemKey     string
}

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
		fullpath = path + cc.Name
	} else {
		fullpath = path + "/" + cc.Name
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(cc.Name + ".crt")
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
		fullpath = path + cc.Name
	} else {
		fullpath = path + "/" + cc.Name
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + ".key")
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

func (ca *CertAuth) writeKey(path string) error {
	var fullpath string
	if strings.HasSuffix(path, "/") {
		fullpath = path + "ca"
	} else {
		fullpath = path + "/" + "ca"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + ".key")
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
		fullpath = path + "ca"
	} else {
		fullpath = path + "/" + "ca"
	}
	err := os.MkdirAll(fullpath, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(fullpath + ".crt")
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
