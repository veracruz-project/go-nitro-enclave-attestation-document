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
	"fmt"
	"math/big"
	pseudoRand "math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	envSeedValue := os.Getenv("GO_DOC_SEED")

	var seed int64
	var err error
	if envSeedValue != "" {
		seed, err = strconv.ParseInt(envSeedValue, 10, 64)
		if err != nil {
			panic("Error: Invalid input for seed\n")
		}

	} else {
		seed = time.Now().UnixNano()
	}
	fmt.Printf("To repeat this test, set an environment variable GO_DOC_SEED to %v\n", seed)
	pseudoRand.Seed(seed)
}

func generateValidTimeRange(expired bool) (time.Time, time.Time) {
	var notBefore time.Time
	var notAfter time.Time
	if expired {
		notBefore = time.Now().Add(-time.Hour * 24)
		notAfter = time.Now().Add(-time.Hour * 1)
	} else {
		notBefore = time.Now()
		notAfter = time.Now().Add(time.Hour * 24 * 180)
	}
	return notBefore, notAfter
}

func generateCertsAndKeys(endCertExpired bool, caCertExpired bool) (*ecdsa.PrivateKey, []byte, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate CA key:%v", err)
	}

	caNotBefore, caNotAfter := generateValidTimeRange(caCertExpired)
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: caNotBefore,
		NotAfter:  caNotAfter,

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

	endNotBefore, endNotAfter := generateValidTimeRange(endCertExpired)
	endTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: endNotBefore,
		NotAfter:  endNotAfter,

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
	pseudoRand.Read(result)
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
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys(false, false)
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := GenerateDocument(PCRs, userData, nonce, endCertDer, [][]byte{caCertDer}, endKey)
	if err != nil {
		t.Fatalf("generateDocument failed:%v\n", err)
	}

	// We now have a ?valid? COSE. Try to authenticate it
	document, err := AuthenticateDocument(messageCbor, *caCert, false)
	if err != nil {
		t.Errorf("Failed to authenticate document:%v\n", err)
	}
	for i := int32(0); i < 16; i++ {
		assert.Equal(t, PCRs[i], document.PCRs[i])
	}
	assert.Equal(t, userData, document.UserData)

}

func Test_AuthenticateDocument_bad_signature(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys(false, false)
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v\n", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := GenerateDocument(PCRs, userData, nonce, endCertDer, [][]byte{caCertDer}, endKey)
	if err != nil {
		t.Fatalf("GenerateDocument failed:%v\n", err)
	}
	// modify the signature so it's not valid
	messageCbor[len(messageCbor)-1] ^= messageCbor[len(messageCbor)-1]
	_, err = AuthenticateDocument(messageCbor[1:], *caCert, true)
	assert.EqualError(t, err, `AuthenticateDocument::Verify failed:verification error`)
}

func Test_AuthenticateDocument_end_entity_cert_expired(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys(true, false)
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v\n", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := GenerateDocument(PCRs, userData, nonce, endCertDer, [][]byte{caCertDer}, endKey)

	_, err = AuthenticateDocument(messageCbor[1:], *caCert, true)
	assert.ErrorContains(t, err, `AuthenticateDocument: Failed to verify certificate chain:x509: certificate has expired or is not yet valid: current time`)
}

func Test_AuthenticateDocument_ca_cert_expired(t *testing.T) {
	endKey, endCertDer, caCert, caCertDer, err := generateCertsAndKeys(false, true)
	if err != nil {
		t.Fatalf("generateCertsAndKeys failed:%v\n", err)
	}
	PCRs, err := generatePCRs()
	if err != nil {
		t.Fatalf("generatePCRs failed:%v\n", err)
	}
	userData := generateRandomSlice(32)
	nonce := generateRandomSlice(32)
	messageCbor, err := GenerateDocument(PCRs, userData, nonce, endCertDer, [][]byte{caCertDer}, endKey)

	_, err = AuthenticateDocument(messageCbor[1:], *caCert, true)
	assert.ErrorContains(t, err, `AuthenticateDocument: Failed to verify certificate chain:x509: certificate has expired or is not yet valid: current time`)
}
