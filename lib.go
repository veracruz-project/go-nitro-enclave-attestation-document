package nitro_eclave_attestation_document

import (
	"crypto/x509"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison-go-cose"
)

type AttestationDocument struct {
	ModuleId: string,
	TimeStamp: uint64,
	Digest: string,
	PCRs: [][]byte,
	Certificate: []byte,
	CABundle: [][]byte,
	PublicKey: []byte,
	UserData: []byte,
	Nonce: []byte,
}

func AuthenticateDocument(data []byte, root_certificate x509.Certificate) (*AttestationDocument, error) {
	// Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	// Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
	var msg cose.Sign1Message
	err := msg.UnmarshalCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument::UnmarshalCBOR failed:%v", err)
	}
	fmt.Printf("msg.Headers:%v\n", msg.Headers)
	fmt.Printf("msg.Payload:%v\n", msg.Payload)
	fmt.Printf("msg.Payload:%v\n", msg.Signature)
	// Step 2. Extract the attestation document from the COSE_Sign1 structure
	var document, err := parse_payload(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:parse_payload failed:%v", err)
	}
	// Step 3. Verify the certificate's chain
	//var certificates []x509.Certificate
	intermediates_pool := x509.NewCertPool()
	for _, this_cert_der in range document.CABundle {
		this_cert, err := x509.ParseCertificate(this_cert_der)
		if err != nil {
			return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
		}
		intermediates_pool.AddCert(this_cert)
	}
	root_pool := x509.NewCertPool()
	root_pool.AddCert(root_certificate)

	end_user_cert, err := x509.ParseCertificate(document.Certificate)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
	}
	cert_verify_options := x509.VerifyOptions {
		Intermediates: intermediates_pool,
		Roots: root_pool,
		KeyUsages: []x509.ExtKeyUsage{ExtKeyUsageAny}
		MaxConstraintComparisons: 0
	}
	_, err := end_user_cert.Verify(cert_verify_options)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument: Failed to verify certificate chain:%v", err)
	}
	// Step 4. Ensure the attestation document is properly signed
	verifier, _ := cose.NewVerifier(cose.AlgorithmES512, end_user_cert.PublicKey)

	err = msg.Verify(nil, verifier)
	if err !=nil {
		return nil, fmt.Errorf("AuthenticateDocument::Verify failed:%v", err)
	}

	// All is good, return the document
	return document
}

func parse_payload(payload: []byte) (*AttestationDocument, err) {
	document := new(AttestationDocument)
	err := cbor.Unmarshal(payload, document)
	if err != nil {
		return nil, fmt.Errorf("parse_payload: cbor.Unmarshal failed:%v\n", err)
	}
	return document, nil
}