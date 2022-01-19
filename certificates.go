package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	secretPKI        = "openvpn-pki-ca"
	secretServer     = "openvpn-pki-server"
	secretClientTmpl = "openvpn-pki-%s"
	secretCRL        = "openvpn-pki-crl"
	secretIndexTxt   = "openvpn-pki-index-txt"
	secretDHandTA    = "openvpn-dh-and-ta"
	certFileName     = "pem.crt"
	privKeyFileName  = "pem.key"
)

//<year><month><day><hour><minute><second>Z
const indexTxtDateFormat = "060102150405Z"

var namespace = "default"

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

type ClientSecret struct {
	ClientCert  ClientCert
	Annotations map[string]string
}

type RevokedCert struct {
	RevokedTime time.Time         `json:"revokedTime"`
	CommonName  string            `json:"commonName"`
	Cert        *x509.Certificate `json:"cert"`
}

func (openVPNPKI *OpenVPNPKI) run() (err error) {
	if _, err := os.Stat(kubeNamespaceFilePath); err == nil {
		file, err := ioutil.ReadFile(kubeNamespaceFilePath)
		if err != nil {
			return err
		}
		namespace = string(file)
	}

	err = openVPNPKI.initKubeClient()
	if err != nil {
		return
	}

	err = openVPNPKI.initPKI()
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	if res, _ := openVPNPKI.checkSecretExist(secretDHandTA); !res {
		err := openVPNPKI.secretGenTaKeyAndDHParam()
		if err != nil {
			log.Error(err)
		}
	}

	err = openVPNPKI.updateFilesFromSecrets()
	if err != nil {
		log.Error(err)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) initPKI() (err error) {
	if res, _ := openVPNPKI.checkSecretExist(secretPKI); res {
		cert, err := openVPNPKI.secretClientCertGet(secretPKI)
		if err != nil {
			return err
		}

		openVPNPKI.CAPrivKeyPEM = cert.PrivKeyPEM
		openVPNPKI.CAPrivKeyRSA = cert.PrivKeyRSA
		openVPNPKI.CACertPEM = cert.CertPEM
		openVPNPKI.CACert = cert.Cert
	} else {
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
			certFileName:    openVPNPKI.CACertPEM.String(),
			privKeyFileName: openVPNPKI.CAPrivKeyPEM.String(),
		}

		err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretPKI}, secretData)
		if err != nil {
			return
		}
	}

	if res, _ := openVPNPKI.checkSecretExist(secretServer); res {
		cert, err := openVPNPKI.secretClientCertGet(secretServer)
		if err != nil {
			return err
		}

		openVPNPKI.ServerPrivKeyPEM = cert.PrivKeyPEM
		openVPNPKI.ServerPrivKeyRSA = cert.PrivKeyRSA
		openVPNPKI.ServerCertPEM = cert.CertPEM
		openVPNPKI.ServerCert = cert.Cert
	} else {
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
			certFileName:    openVPNPKI.ServerCertPEM.String(),
			privKeyFileName: openVPNPKI.ServerPrivKeyPEM.String(),
		}

		err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretServer, Labels: map[string]string{"index": "txt", "usage": "serverAuth"}}, secretData)
		if err != nil {
			return
		}
	}

	return
}

func (openVPNPKI *OpenVPNPKI) initKubeClient() (err error) {
	config, _ := rest.InClusterConfig()
	openVPNPKI.KubeClient, err = kubernetes.NewForConfig(config)
	return
}

func (openVPNPKI *OpenVPNPKI) secretGetIndexTxt() (indexTxt string, err error) {
	secret, err := openVPNPKI.secretGet(secretIndexTxt)
	indexTxt = string(secret.Data["index.txt"])
	return
}

func (openVPNPKI *OpenVPNPKI) indexTxtUpdate() (err error) {
	secrets, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: "index=txt"})
	if err != nil {
		return
	}

	var indexTxt string
	for _, secret := range secrets.Items {
		certPEM := bytes.NewBuffer(secret.Data[certFileName])
		cert, err := decodeCert(certPEM.Bytes())
		if err != nil {
			return nil
		}

		if secret.Annotations["revokedAt"] == "" {
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "V", cert.NotAfter.Format(indexTxtDateFormat), cert.SerialNumber.String(), "unknown", "/CN="+cert.DNSNames[0])
		} else if cert.NotAfter.Before(time.Now()) {
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "E", cert.NotAfter.Format(indexTxtDateFormat), cert.SerialNumber.String(), "unknown", "/CN="+cert.DNSNames[0])
		} else {
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", "R", cert.NotAfter.Format(indexTxtDateFormat), secret.Annotations["revokedAt"], cert.SerialNumber.String(), "unknown", "/CN="+cert.DNSNames[0])
		}

	}

	data := map[string]string{"index.txt": indexTxt}

	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{Name: secretIndexTxt},
		StringData: data,
		Type:       v1.SecretTypeOpaque,
	}

	if res, _ := openVPNPKI.checkSecretExist(secretIndexTxt); !res {
		_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	} else {
		_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	}

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaGenCRL() (err error) {
	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	secrets, err := openVPNPKI.secretGetClients()
	if err != nil {
		return
	}

	var revoked []*RevokedCert

	for _, secret := range secrets {
		if secret.Annotations["revokedAt"] != "" {
			revokedAt, err := time.Parse(indexTxtDateFormat, secret.Annotations["revokedAt"])
			if err != nil {
				log.Warning(err)
			}
			revoked = append(revoked, &RevokedCert{RevokedTime: revokedAt, Cert: secret.ClientCert.Cert})
		}
	}

	crl, err := genCRL(revoked, openVPNPKI.CACert, openVPNPKI.CAPrivKeyRSA)
	if err != nil {
		return
	}

	secretData := map[string]string{
		"crl.pem": crl.String(),
	}

	err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretCRL}, secretData)

	if res, _ := openVPNPKI.checkSecretExist(secretCRL); !res {
		err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretCRL}, secretData)
	} else {
		err = openVPNPKI.secretUpdate(metav1.ObjectMeta{Name: secretCRL}, secretData)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaBuildClient(commonName string) (err error) {
	if openVPNPKI.checkUserExist(commonName) == true {
		return errors.New(fmt.Sprintf("User \"%s\" already exists\n", commonName))
	}

	clientPrivKeyPEM, err := genPrivKey()
	if err != nil {
		return
	}

	clientPrivKeyRSA, err := decodePrivKey(clientPrivKeyPEM.Bytes())
	if err != nil {
		return
	}

	clientCertPEM, _ := genClientCert(clientPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, commonName)
	clientCert, err := decodeCert(clientCertPEM.Bytes())

	secretData := map[string]string{
		certFileName:    clientCertPEM.String(),
		privKeyFileName: clientPrivKeyPEM.String(),
	}

	name := fmt.Sprintf(secretClientTmpl, clientCert.SerialNumber)
	annotations := map[string]string{
		"commonName": commonName,
		"notBefore":  clientCert.NotBefore.Format(indexTxtDateFormat),
		"notAfter":   clientCert.NotAfter.Format(indexTxtDateFormat),
		"revokedAt":  "",
		"serial":     clientCert.SerialNumber.String(),
	}
	labels := map[string]string{"index": "txt", "usage": "clientAuth"}

	err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: name, Labels: labels, Annotations: annotations}, secretData)
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaGetCACert() string {
	return openVPNPKI.CACertPEM.String()
}

func (openVPNPKI *OpenVPNPKI) easyrsaGetClientCert(commonName string) (cert ClientCert) {
	clients, err := openVPNPKI.secretGetClients()
	if err != nil {
		log.Error(err)
	}

	var serialNumber string
	for _, client := range clients {
		if client.Annotations["commonName"] == commonName {
			serialNumber = client.ClientCert.Cert.SerialNumber.String()
			break
		}
	}

	cert, err = openVPNPKI.secretClientCertGet(fmt.Sprintf(secretClientTmpl, serialNumber))
	if err != nil {
		log.Error(err)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaRevoke(commonName string) (err error) {
	clients, err := openVPNPKI.secretGetClients()

	var serialNumber string
	for _, client := range clients {
		if client.Annotations["commonName"] == commonName {
			serialNumber = client.ClientCert.Cert.SerialNumber.String()
			break
		}
	}

	secret, err := openVPNPKI.secretGet(fmt.Sprintf(secretClientTmpl, serialNumber))
	if err != nil {
		return
	}

	if secret.Annotations["revokedAt"] != "" {
		log.Warnf("User \"%s\" already revoked\n", commonName)
		return
	}

	secret.Annotations["revokedAt"] = time.Now().Format(indexTxtDateFormat)

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaUnrevoke(commonName string) (err error) {
	clients, err := openVPNPKI.secretGetClients()

	var serialNumber string
	for _, client := range clients {
		if client.Annotations["commonName"] == commonName {
			serialNumber = client.ClientCert.Cert.SerialNumber.String()
			break
		}
	}

	secret, err := openVPNPKI.secretGet(fmt.Sprintf(secretClientTmpl, serialNumber))
	if err != nil {
		return
	}

	secret.Annotations["revokedAt"] = ""

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()

	return
}

func (openVPNPKI *OpenVPNPKI) checkUserExist(commonName string) bool {
	secrets, err := openVPNPKI.secretGetClients()
	if err != nil {
		log.Error(err)
	}

	for _, secret := range secrets {
		if secret.Annotations["commonName"] == commonName {
			return true
		}
	}

	return false
}

func (openVPNPKI *OpenVPNPKI) checkSecretExist(name string) (bool, string) {
	secret, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		log.Debug(err)
		return false, ""
	}
	return true, secret.ResourceVersion
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

func (openVPNPKI *OpenVPNPKI) secretUpdate(objectMeta metav1.ObjectMeta, data map[string]string) (err error) {
	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: objectMeta,
		StringData: data,
		Type:       v1.SecretTypeOpaque,
	}
	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretClientCertGet(name string) (cert ClientCert, err error) {
	secret, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return
	}

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

func (openVPNPKI *OpenVPNPKI) secretGet(name string) (secret *v1.Secret, err error) {
	secret, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretGetClients() (clientSecrets []ClientSecret, err error) {
	secrets, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: "usage=clientAuth"})

	for _, secret := range secrets.Items {
		tmpCertPEM := bytes.NewBuffer(secret.Data[certFileName])
		tmpCert, err := decodeCert(tmpCertPEM.Bytes())
		if err != nil {
			log.Println(1)
			return nil, err
		}
		tmpPrivKeyPEM := bytes.NewBuffer(secret.Data[privKeyFileName])
		tmpPrivKey, err := decodePrivKey(tmpPrivKeyPEM.Bytes())
		if err != nil {
			log.Println(tmpCert.DNSNames[0])
			return nil, err
		}
		clientSecrets = append(clientSecrets, ClientSecret{
			ClientCert:  ClientCert{PrivKeyPEM: tmpPrivKeyPEM, PrivKeyRSA: tmpPrivKey, CertPEM: tmpCertPEM, Cert: tmpCert},
			Annotations: secret.Annotations,
		})
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
func genCRL(certs []*RevokedCert, ca *x509.Certificate, caKey *rsa.PrivateKey) (crlPEM *bytes.Buffer, err error) {
	var revokedCertificates []pkix.RevokedCertificate
	// TODO store RevocationTime somewhere
	for _, cert := range certs {
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.Cert.SerialNumber, RevocationTime: cert.RevokedTime})
	}
	revocationList := &x509.RevocationList{
		//SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
		//ExtraExtensions: []pkix.Extension{},
	}

	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, ca, caKey)
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

func (openVPNPKI *OpenVPNPKI) updateFilesFromSecrets() (err error) {
	ca, err := openVPNPKI.secretClientCertGet(secretPKI)
	if err != nil {
		return
	}

	server, err := openVPNPKI.secretClientCertGet(secretServer)
	if err != nil {
		return
	}

	secret, err := openVPNPKI.secretGet(secretDHandTA)
	takey := secret.Data["ta.key"]
	dhparam := secret.Data["dh.pem"]

	if _, err := os.Stat(fmt.Sprintf("%s/pki/issued", *easyrsaDirPath)); os.IsNotExist(err) {
		err = os.MkdirAll(fmt.Sprintf("%s/pki/issued", *easyrsaDirPath), 0755)
	}

	if _, err := os.Stat(fmt.Sprintf("%s/pki/private", *easyrsaDirPath)); os.IsNotExist(err) {
		err = os.MkdirAll(fmt.Sprintf("%s/pki/private", *easyrsaDirPath), 0755)
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/ca.crt", *easyrsaDirPath), ca.CertPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/issued/server.crt", *easyrsaDirPath), server.CertPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/private/server.key", *easyrsaDirPath), server.PrivKeyPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/ta.key", *easyrsaDirPath), takey, 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/dh.pem", *easyrsaDirPath), dhparam, 0600)
	if err != nil {
		return
	}

	err = openVPNPKI.updateCRLOnDisk()
	return
}

func (openVPNPKI *OpenVPNPKI) updateCRLOnDisk() (err error) {
	secret, err := openVPNPKI.secretGet(secretCRL)
	crl := secret.Data["crl.pem"]
	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/crl.pem", *easyrsaDirPath), crl, 0600)
	return
}

func (openVPNPKI *OpenVPNPKI) secretGenTaKeyAndDHParam() (err error) {
	taKeyPath := "/tmp/ta.key"
	cmd := exec.Command("bash", "-c", fmt.Sprintf("/usr/sbin/openvpn --genkey --secret %s", taKeyPath))
	stdout, err := cmd.CombinedOutput()
	log.Info(fmt.Sprintf("/usr/sbin/openvpn --genkey --secret %s: %s", taKeyPath, string(stdout)))
	if err != nil {
		return
	}
	taKey, err := ioutil.ReadFile(taKeyPath)

	dhparamPath := "/tmp/dh.pem"
	cmd = exec.Command("bash", "-c", fmt.Sprintf("openssl dhparam -out %s 2048", dhparamPath))
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	dhparam, err := ioutil.ReadFile(dhparamPath)

	secretData := map[string]string{
		"ta.key": string(taKey),
		"dh.pem": string(dhparam),
	}

	err = openVPNPKI.secretCreate(metav1.ObjectMeta{Name: secretDHandTA}, secretData)
	if err != nil {
		return
	}

	return
}
