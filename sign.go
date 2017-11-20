package cms

import (
	"crypto"
	"crypto/x509"
)

func (sd *SignedData) Sign(cert *x509.Certificate, signer crypto.Signer) error {
	return nil
}
