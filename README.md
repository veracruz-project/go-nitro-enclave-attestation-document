# go-nitro-enclave-attestation-document
Golang module for decoding and verifying AWS Nitro enclave attestation documents for golang projects.

You, yes! You can authenticate and parse AWS Nitro Enclave Attestation documents!

You probably have questions.

Like, what are AWS Nitro Enclaves? Here's some info: https://aws.amazon.com/ec2/nitro/nitro-enclaves/

Also, what are AWS Nitro Enclave Attestation Documents? Here's some more info: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html

and here's some more: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

Now that you've read every word on those links (yeah, right), here's how to use this module.

When you receive an attestation document (as `document_data []byte`), call:
```

document, err := AuthenticateDocument(document_data, root_certificate)
if err != nil {
  // either the signature verification on the document data failed
  // or the document_data was malformed, or the root_certificate had a problem,
  // or any number of things went wrong.
}
```
You should fetch the AWS Nitro Root Certificate from this link here: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

That link gives you the certificate in PEM format. The `AuthenticateDocument` function above requires the certificate to be a `x509.Certificate`. Converting from PEM to `x509.Certificate` is left as an exercise for the reader.

This crate is intended for use from golang projects. If you need support in another language, that is mostly left up to the reader. However, we have also implemented this functionality for the Rust programming language, available here: https://github.com/veracruz-project/nitro-enclave-attestation-document
