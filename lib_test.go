//! tests for the AWS Nitro Attestation Document module
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

package nitro_eclave_attestation_document

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

var testTime time.Time = time.Date(2022, 11, 9, 23, 0, 0, 0, time.UTC)
var rootCert x509.Certificate

func init() {
	certPemBytes, err := os.ReadFile("test/aws_nitro_root_cert.pem")
	if err != nil {
		panic("Read of AWS Nitro root certificate file failed")
	}
	cert_block, _ := pem.Decode(certPemBytes)
	if cert_block == nil {
		panic("Could not decode PEM into DER")
	}

	cert, err := x509.ParseCertificate(cert_block.Bytes)
	if err != nil {
		panic("Could not parse DER into certificate")
	}
	rootCert = *cert
}

func generateDocument(PCRs map[int32][]byte, userData []byte, nonce []byte, signingCertDer []byte, caBundle []byte, signingKey *ecdsa.PrivateKey) ([]byte, error) {
	document := AttestationDocument{
		ModuleId:    "MyId",
		TimeStamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        PCRs,
		Certificate: signingCertDer,
		CABundle: [][]byte{
			caBundle,
		},
		PublicKey: []byte{},
		UserData:  userData,
		Nonce:     nonce,
	}
	payload, err := cbor.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("cbor Marshal of document failed:%v", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	signer, err := cose.NewSigner(cose.AlgorithmES384, signingKey)
	if err := msg.Sign(rand.Reader, []byte{}, signer); err != nil {
		return nil, fmt.Errorf("Failed to sign:%v\n", err)
	}

	messageCbor, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal CBOR:%v\n", err)
	}
	return messageCbor, nil
}

func generateCertsAndKeys() (*ecdsa.PrivateKey, []byte, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate CA key:%v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertDer, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate CA Certificate:%v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDer)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to convert CA Cert der to certificate:%v", err)
	}

	endKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate end key:%v", err)
	}
	endTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	endCertDer, err := x509.CreateCertificate(rand.Reader, &endTemplate, caCert, &endKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Failed to generate end certificate:%v", err)
	}
	return endKey, endCertDer, caCert, caCertDer, nil
}

const NUM_PCRS = 16

func generateRandomSlice(size int32) []byte {
	result := make([]byte, size)
	rand.Read(result)
	return result
}
func generatePCRs() (map[int32][]byte, error) {
	pcrs := make(map[int32][]byte)
	for i := int32(0); i < NUM_PCRS; i++ {
		pcrs[i] = generateRandomSlice(96)
	}
	return pcrs, nil
}

func Test_AuthenticateDocument_ok(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys()
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := generateDocument(PCRs, userData, nonce, endCertDer, caCertDer, endKey)
	if err != nil {
		t.Fatalf("generateDocument failed:%v\n", err)
	}

	// We now have a ?valid? COSE. Try to authenticate it
	document, err := AuthenticateDocument(messageCbor[1:], *caCert)
	if err != nil {
		t.Errorf("Failed to authenticate document:%v\n", err)
	}
	for i := int32(0); i < 16; i++ {
		assert.Equal(t, PCRs[i], document.PCRs[i])
	}
	assert.Equal(t, userData, document.UserData)

}

func Test_AuthenticateDocument_bad_signature(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys()
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v\n", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := generateDocument(PCRs, userData, nonce, endCertDer, caCertDer, endKey)
	if err != nil {
		t.Fatalf("generateDocument failed:%v\n", err)
	}
	// modify the signature so it's not valid
	messageCbor[len(messageCbor)-1] ^= messageCbor[len(messageCbor)-1]
	_, err = AuthenticateDocument(messageCbor[1:], *caCert)
	assert.EqualError(t, err, `AuthenticateDocument::Verify failed:verification error`)
}

func Test_AuthenticateDocument_expired(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/aws_nitro_document_bad_sig.cbor")
	require.NoError(t, err)

	_, err = AuthenticateDocument(tokenBytes, rootCert)
	assert.ErrorContains(t, err, `AuthenticateDocument: Failed to verify certificate chain:x509: certificate has expired or is not yet valid: current time`)
}
