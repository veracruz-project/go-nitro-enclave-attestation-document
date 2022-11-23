//! A go module for authenticating and parsing AWS nitro enclave attestation documents
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
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type AttestationDocument struct {
	ModuleId    string
	TimeStamp   uint64
	Digest      string
	PCRs        map[int32][]byte
	Certificate []byte
	CABundle    [][]byte
	PublicKey   []byte
	UserData    []byte
	Nonce       []byte
}

/// Authenticate an AWS Nitro Enclave attestation document with the provided root certificate.
/// If authentication passes, return the generated AttestationDocument representing the fields
/// from the provided CBOR data
func AuthenticateDocument(data []byte, root_certificate x509.Certificate) (*AttestationDocument, error) {
	// Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	// Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
	var msg cose.Sign1Message
	// The go-cose library wants a special prefix on the data that I'm not seeing (and that the rust implementation
	// of cose is not expecting. Adding it to make it happy)
	data = append([]byte{0xd2}, data...)
	err := msg.UnmarshalCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument::UnmarshalCBOR failed:%v", err)
	}

	// Step 2. Extract the attestation document from the COSE_Sign1 structure
	document, err := parsePayload(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:parsePayload failed:%v", err)
	}
	// Step 3. Verify the certificate's chain
	intermediates_pool := x509.NewCertPool()
	for _, this_cert_der := range document.CABundle {
		this_cert, err := x509.ParseCertificate(this_cert_der)
		if err != nil {
			return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
		}
		intermediates_pool.AddCert(this_cert)
	}
	root_pool := x509.NewCertPool()
	root_pool.AddCert(&root_certificate)

	end_user_cert, err := x509.ParseCertificate(document.Certificate)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
	}
	cert_verify_options := x509.VerifyOptions{
		Intermediates:             intermediates_pool,
		Roots:                     root_pool,
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxConstraintComparisions: 0, // sic: This typo is correct per the documentation, it will not be fixed
		// per this issue: https://github.com/golang/go/issues/27969
	}
	_, err = end_user_cert.Verify(cert_verify_options)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument: Failed to verify certificate chain:%v", err)
	}
	// Step 4. Ensure the attestation document is properly signed
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, end_user_cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("NewVerifier failed:%v\n", err)
	}
	err = msg.Verify(nil, verifier)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument::Verify failed:%v", err)
	}

	// All is good, return the document
	return document, nil
}

func parsePayload(payload []byte) (*AttestationDocument, error) {
	document := new(AttestationDocument)
	err := cbor.Unmarshal(payload, document)
	if err != nil {
		return nil, fmt.Errorf("parse_payload: cbor.Unmarshal failed:%v\n", err)
	}
	return document, nil
}
