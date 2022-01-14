package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	secretPKI        = "openvpn-pki"
	secretServer     = "openvpn-pki-server"
	secretRevoked    = "openvpn-pki-revoked"
	secretClientTmpl = "openvpn-pki-%s"
	namespace        = "default"
	certFileName     = "pem.crt"
	privKeyFileName  = "pem.key"
)

type OpenVPNPKI struct {
	CAPrivKeyRSA     *rsa.PrivateKey
	CAPrivKeyPEM     *bytes.Buffer
	CACert           *x509.Certificate
	CACertPEM        *bytes.Buffer
	ServerPrivKeyRSA *rsa.PrivateKey
	ServerPrivKeyPEM *bytes.Buffer
	ServerCert       *x509.Certificate
	ServerCertPEM    *bytes.Buffer
	ClientCerts      []ClientCert
	RevokedCerts     []RevokedCert
	KubeClient       *kubernetes.Clientset
}

type ClientCert struct {
	PrivKeyRSA *rsa.PrivateKey
	PrivKeyPEM *bytes.Buffer
	Cert       *x509.Certificate
	CertPEM    *bytes.Buffer
}

type RevokedCert struct {
	RevokedTime time.Time
	CertCN      string
}

func (openVPNPKI *OpenVPNPKI) initKubeClient() (err error) {
	config, _ := rest.InClusterConfig()
	openVPNPKI.KubeClient, err = kubernetes.NewForConfig(config)
	return
}

func (openVPNPKI *OpenVPNPKI) initPKI() (err error) {
	if !openVPNPKI.checkSecretExist(secretPKI) {
		openVPNPKI.CAPrivKeyPEM, err = genPrivKey()
		if err != nil {
			return
		}
		openVPNPKI.CAPrivKeyRSA, err = decodePrivKey(openVPNPKI.CAPrivKeyPEM.Bytes())

		openVPNPKI.CACertPEM, _ = genCA(openVPNPKI.CAPrivKeyRSA)
		openVPNPKI.CACert, err = decodeCert(openVPNPKI.CACertPEM.Bytes())
		if err != nil {
			return
		}

		secretData := map[string]string{
			certFileName: openVPNPKI.CACertPEM.String(),
			privKeyFileName: openVPNPKI.CAPrivKeyPEM.String(),
		}

		err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretPKI, Labels: map[string]string{"type": "ca"}}, secretData)
		if err != nil {
			return
		}
	}

	if !openVPNPKI.checkSecretExist(secretServer) {
		openVPNPKI.ServerPrivKeyPEM, err = genPrivKey()
		if err != nil {
			return
		}

		openVPNPKI.ServerPrivKeyRSA, err = decodePrivKey(openVPNPKI.ServerPrivKeyPEM.Bytes())
		if err != nil {
			return
		}

		openVPNPKI.ServerCertPEM, _ = genServerCert(openVPNPKI.ServerPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, "server")
		openVPNPKI.ServerCert, err = decodeCert(openVPNPKI.ServerCertPEM.Bytes())

		secretData := map[string]string{
			certFileName: openVPNPKI.ServerCertPEM.String(),
			privKeyFileName: openVPNPKI.ServerPrivKeyPEM.String(),
		}

		err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretServer, Labels: map[string]string{"type": "server"}}, secretData)
		if err != nil {
			return
		}
	}

	return
}

func (openVPNPKI *OpenVPNPKI) checkSecretExist(name string) bool {
	_, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		log.Debug(err)
		return false
	}
	return true
}

func (openVPNPKI *OpenVPNPKI) secretCreate(objectMeta metav1.ObjectMeta, data map[string]string) (err error) {
	if objectMeta.Name == "nil" {
		fmt.Println("Name empty")
	}
	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: objectMeta,
		StringData: data,
		Type:       v1.SecretTypeOpaque,
	}
	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretUpdate(name string, data map[string]string) (err error) {
	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		StringData: data,
		Type:       v1.SecretTypeOpaque,
	}
	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretGet(name string) (cert ClientCert, err error) {
	secret, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})

	cert.CertPEM = bytes.NewBuffer(secret.Data[certFileName])
	cert.Cert, err = decodeCert(cert.CertPEM.Bytes())
	if err != nil {
		return
	}

	cert.PrivKeyPEM = bytes.NewBuffer(secret.Data[privKeyFileName])
	cert.PrivKeyRSA, err = decodePrivKey(cert.PrivKeyPEM.Bytes())
	if err != nil {
		return
	}

	return
}

//func (openVPNPKI *OpenVPNPKI) secretGetL(name string) (cert ClientCert, err error) {
//	secret, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(),metav1.ListOptions{LabelSelector: "type=server"})
//	fmt.Println(secret)
//	return
//}

func (openVPNPKI *OpenVPNPKI) secretGetClients() (certs []ClientCert, err error) {
	secrets, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: "type=client"})

	for _, secret := range secrets.Items {
		tmpCertPEM := bytes.NewBuffer(secret.Data[certFileName])
		tmpCert, err := decodeCert(tmpCertPEM.Bytes())
		if err != nil {
			return nil, err
		}
		tmpPrivKeyPEM := bytes.NewBuffer(secret.Data[privKeyFileName])
		tmpPrivKey, err := decodePrivKey(tmpPrivKeyPEM.Bytes())
		if err != nil {
			return nil, err
		}
		certs = append(certs, ClientCert{PrivKeyPEM: tmpPrivKeyPEM, PrivKeyRSA: tmpPrivKey, CertPEM: tmpCertPEM, Cert: tmpCert})
	}

	return
}

func decodeCert(certPEMBytes []byte) (cert *x509.Certificate, err error) {
	certPem, _ := pem.Decode(certPEMBytes)
	certPemBytes := certPem.Bytes

	cert, err = x509.ParseCertificate(certPemBytes)
	if err != nil {
		return
	}

	return
}

// decode private key from PEM to RSA format
func decodePrivKey(privKey []byte) (key *rsa.PrivateKey, err error) {
	privKeyPem, _ := pem.Decode(privKey)
	key, err = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	return
}

// return PEM encoded private key
func genPrivKey() (privKeyPEM *bytes.Buffer, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)

	privKeyPEM = new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return
}

// return PEM encoded certificate
func genCA(privKey *rsa.PrivateKey) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)

	issuerTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          issuerSerial,
		Subject: pkix.Name{
			CommonName: "ca",
		},

		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genServerCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, serialNumberRange)

	//ca.SubjectKeyId = nil

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genClientCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, serialNumberRange)

	//ca.SubjectKeyId = nil

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded CRL
func genCRL(certs []*x509.Certificate, ca, caKey []byte) (crlPEM *bytes.Buffer, err error) {
	var revokedCertificates []pkix.RevokedCertificate
	// TODO store RevocationTime somewhere
	for _, cert := range certs {
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.SerialNumber, RevocationTime: time.Now()})
	}
	revocationList := &x509.RevocationList{
		//SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
		//ExtraExtensions: []pkix.Extension{},
	}

	issuer, err := decodeCert(ca)
	if err != nil {
		return nil, err
	}

	priv, err := decodePrivKey(caKey)
	if err != nil {
		return nil, err
	}

	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, issuer, priv)
	if err != nil {
		return nil, err
	}

	crlPEM = new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return
	}

	return
}
