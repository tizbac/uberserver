package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func createSelfSignedCert(certname, keyname string) error {
	fmt.Printf("Generating self-signed certificate %v\n", []string{certname, keyname})

	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serial, _ := big.NewInt(0).SetString("1000", 10)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"DE"},
			Province:           []string{"uberserver self-signed certificate"},
			Locality:           []string{"-"},
			Organization:       []string{"-"},
			OrganizationalUnit: []string{"spring rts"},
			CommonName:         "-"},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &k.PublicKey, k)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certname)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return err
	}
	certOut.Close()
	os.Chmod(certname, 0o600)

	keyOut, err := os.Create(keyname)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}); err != nil {
		keyOut.Close()
		return err
	}
	keyOut.Close()
	os.Chmod(keyname, 0o600)

	return nil
}

// loadCertificates loads the PEM certificate chain + private key, generating
// a self-signed pair when both files are missing (mirrors DataHandler.loadCertificates).
func loadCertificates(certfile, keyfile string) (*tls.Certificate, error) {
	if _, err := os.Stat(certfile); os.IsNotExist(err) {
		if _, err2 := os.Stat(keyfile); os.IsNotExist(err2) {
			if err := createSelfSignedCert(certfile, keyfile); err != nil {
				return nil, err
			}
		}
	}
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
