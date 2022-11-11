package nitro_eclave_attestation_document

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_AuthenticateDocument_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/aws_nitro_document.cbor")
	require.NoError(t, err)
	expectedPcr0 := [48]byte {
		34, 249, 225, 201, 73, 32, 141, 165, 94, 176, 27, 155, 159, 200, 143, 135, 
		69, 79, 119, 186, 19, 63, 13, 130, 50, 11, 80, 150, 33, 201, 36, 130,
		21, 42, 153, 208, 161, 35, 53, 185, 113, 120, 192, 45, 111, 151, 125, 1,
	}
	expectedNonce := [32]byte {
		198, 120, 200, 97, 53, 222, 83, 157, 24, 58, 207, 245, 136, 134, 217, 141,
		251, 152, 35, 4, 26, 249, 249, 52, 191, 144, 154, 192, 248, 217, 98, 69,
	}
 	

	expectedUserData := [32]byte {
		124, 55, 16, 128, 121, 179, 232, 163, 109, 138, 121, 112, 222, 29, 109, 79,
		241, 70, 30, 14, 53, 217, 85, 124, 77, 120, 157, 245, 224, 87, 102, 32,
	}

	doc, err := AuthenticateDocumentTest(tokenBytes, rootCert, testTime)
	assert.Equal(t, expectedPcr0[:], doc.PCRs[0])
	assert.Equal(t, expectedNonce[:], doc.Nonce)
	assert.Equal(t, expectedUserData[:], doc.User_Data)
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