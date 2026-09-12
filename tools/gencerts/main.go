// Command gencerts (re)issues the DNAS gateway certificates.
//
// WARNING: the set it produced in September 2026 (certs/reissued-2026) is
// rejected by titles that accept the 2016 originals in certs/. Whatever the
// console checks, the originals satisfy it and these do not - so this tool is
// kept as a starting point for experiments, not as the way to refresh certs/.
//
// The PS2's DNAS library embeds an OpenSSL of the 0.9.6/0.9.7 era, so the
// certificates are deliberately old-fashioned: RSA-1024, SHA-1 signatures
// (those OpenSSL versions know neither SHA-256 nor anything newer), a validity
// window that ends before the 32-bit time_t rollover in 2038 and starts far
// enough in the past to survive a console whose clock was never set. Subjects
// are kept identical to the original DNASrep certificates, including the
// forged "VeriSign Class 3 Public Primary CA" issuer that the console trusts by
// name. The per-region leaf keys are reused so nothing else changes; the CA key
// is generated on first run and kept next to the CA certificate for the next
// re-issue.
//
//	go run ./tools/gencerts -certdir ./certs
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2037, 12, 31, 23, 59, 59, 0, time.UTC)

	caSubject = pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"VeriSign, Inc."},
		OrganizationalUnit: []string{"Class 3 Public Primary Certification Authority"},
	}

	// The hostnames Apache answered for per region (ServerName/ServerAlias in
	// the original dnas.conf). CN stays gate1.<region>, the rest go into SANs.
	regionHosts = map[string][]string{
		"jp": {"gate1.jp.dnas.playstation.org", "ts01.jp.dnas.playstation.org",
			"dnns-p01.jp.dnas.playstation.org", "dnns-r01.jp.dnas.playstation.org",
			"bbn01.jp.dnas.playstation.org", "bbn02.jp.dnas.playstation.org"},
		"eu": {"gate1.eu.dnas.playstation.org", "ts01.eu.dnas.playstation.org",
			"dnns-p01.eu.dnas.playstation.org", "dnns-r01.eu.dnas.playstation.org"},
		"us": {"gate1.us.dnas.playstation.org", "ts01.us.dnas.playstation.org",
			"dnns-p01.us.dnas.playstation.org", "dnns-r01.us.dnas.playstation.org"},
	}
	// Country and organisation spelling exactly as in the 2016 originals.
	regionCountry = map[string]string{"jp": "JP", "eu": "US", "us": "US"}
	regionOrg     = map[string]string{"jp": "Cyberpunks", "eu": "cyberpunks", "us": "Cyberpunks"}
)

func main() {
	certdir := flag.String("certdir", "./certs", "directory holding cert-{jp,eu,us}-key.pem; certificates are written here")
	flag.Parse()

	caKey, err := loadOrCreateCAKey(filepath.Join(*certdir, "ca-key.pem"))
	if err != nil {
		log.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               caSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA1WithRSA,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	if err := writePEM(filepath.Join(*certdir, "ca-cert.pem"), "CERTIFICATE", caDER); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote ca-cert.pem (%s .. %s)", notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02"))

	for _, region := range []string{"jp", "eu", "us"} {
		keyPath := filepath.Join(*certdir, "cert-"+region+"-key.pem")
		key, err := loadRSAKey(keyPath)
		if err != nil {
			log.Fatalf("%s: %v", keyPath, err)
		}
		hosts := regionHosts[region]
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject: pkix.Name{
				Country:      []string{regionCountry[region]},
				Organization: []string{regionOrg[region]},
				CommonName:   hosts[0],
				ExtraNames: []pkix.AttributeTypeAndValue{{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1}, // emailAddress, as in the originals
					Value: "the_fog@1337.rip",
				}},
			},
			DNSNames:           hosts,
			NotBefore:          notBefore,
			NotAfter:           notAfter,
			KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			SignatureAlgorithm: x509.SHA1WithRSA,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			log.Fatalf("%s certificate: %v", region, err)
		}
		out := filepath.Join(*certdir, "cert-"+region+".pem")
		if err := writePEM(out, "CERTIFICATE", der); err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote %s (CN=%s)", filepath.Base(out), hosts[0])
	}
}

func loadOrCreateCAKey(path string) (*rsa.PrivateKey, error) {
	if key, err := loadRSAKey(path); err == nil {
		log.Printf("using existing CA key %s", path)
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	if err := writePEM(path, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return nil, err
	}
	log.Printf("generated new CA key %s", path)
	return key, nil
}

func loadRSAKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return key, nil
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644)
}

// serial derives a random positive serial number.
func serial() *big.Int {
	var b [8]byte
	rand.Read(b[:])
	b[0] &= 0x7f
	return new(big.Int).SetBytes(b[:])
}
