package cms

import (
	"crypto"
	"crypto/x509"
)

// Sign creates a CMS SignedData from the content and signs it with the
// certificate and signer. The DER encoded CMS message is returned.
func Sign(data []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Sign(cert, signer); err != nil {
		return nil, err
	}

	return sd.ToDER()
}

// SignDetached creates a detached CMS SignedData from the content and signs it
// with the certificate and signer. The DER encoded CMS message is returned.
func SignDetached(data []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Sign(cert, signer); err != nil {
		return nil, err
	}

	sd.Detached()

	return sd.ToDER()
}

// Sign adds a signature to the SignedData.
func (sd *SignedData) Sign(cert *x509.Certificate, signer crypto.Signer) error {
	return sd.psd.AddSignerInfo(cert, signer)
}
