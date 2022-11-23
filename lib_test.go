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

func Test_AuthenticateDocument_ok(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys()
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs := map[int32][]byte{
		0:  {34, 249, 225, 201, 73, 32, 141, 165, 94, 176, 27, 155, 159, 200, 143, 135, 69, 79, 119, 186, 19, 63, 13, 130, 50, 11, 80, 150, 33, 201, 36, 130, 21, 42, 153, 208, 161, 35, 53, 185, 113, 120, 192, 45, 111, 151, 125, 1},
		1:  {188, 223, 5, 254, 252, 202, 168, 229, 91, 242, 200, 214, 222, 233, 231, 155, 191, 243, 30, 52, 191, 40, 169, 154, 161, 158, 107, 41, 195, 126, 232, 11, 33, 74, 65, 75, 118, 7, 35, 110, 223, 38, 252, 183, 134, 84, 230, 63},
		2:  {0, 148, 62, 168, 89, 20, 15, 237, 116, 225, 2, 95, 228, 26, 237, 179, 135, 128, 234, 229, 101, 107, 63, 158, 249, 180, 176, 230, 17, 19, 80, 49, 85, 68, 219, 62, 252, 218, 5, 114, 81, 8, 247, 43, 42, 177, 65, 247},
		3:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		4:  {69, 84, 4, 35, 57, 230, 161, 221, 250, 200, 157, 183, 218, 88, 35, 29, 86, 25, 7, 55, 41, 52, 67, 51, 175, 240, 85, 66, 154, 190, 236, 107, 0, 111, 129, 177, 157, 17, 118, 0, 27, 130, 145, 248, 133, 40, 49, 6},
		5:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		6:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		7:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		8:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		9:  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		10: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		11: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		12: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		13: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		14: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		15: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	userData := []byte{124, 55, 16, 128, 121, 179, 232, 163, 109, 138, 121, 112, 222, 29, 109, 79, 241, 70, 30, 14, 53, 217, 85, 124, 77, 120, 157, 245, 224, 87, 102, 32}
	nonce := []byte{198, 120, 200, 97, 53, 222, 83, 157, 24, 58, 207, 245, 136, 134, 217, 141, 251, 152, 35, 4, 26, 249, 249, 52, 191, 144, 154, 192, 248, 217, 98, 69}
	messageCbor, err := generateDocument(PCRs, userData, nonce, endCertDer, caCertDer, endKey)

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
	tokenBytes, err := os.ReadFile("test/aws_nitro_document_bad_sig.cbor")
	require.NoError(t, err)

	_, err = AuthenticateDocumentTest(tokenBytes, rootCert, testTime)
	assert.EqualError(t, err, `AuthenticateDocument::Verify failed:verification error`)
}

func Test_AuthenticateDocument_expired(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/aws_nitro_document_bad_sig.cbor")
	require.NoError(t, err)

	_, err = AuthenticateDocument(tokenBytes, rootCert)
	assert.ErrorContains(t, err, `AuthenticateDocument: Failed to verify certificate chain:x509: certificate has expired or is not yet valid: current time`)
}
