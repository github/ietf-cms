package cms

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
)

// Verify verifies the SingerInfos' signatures.
func (sd *SignedData) Verify() error {
	data, err := sd.psd.EncapContentInfo.DataEContent()
	if err != nil {
		return err
	}
	if data == nil {
		return errors.New("detached signature")
	}

	return sd.verify(data)
}

// VerifyDetached verifies the SingerInfos' detached signatures over the
// provided message.
func (sd *SignedData) VerifyDetached(message []byte) error {
	if sd.psd.EncapContentInfo.EContent.Bytes != nil {
		return errors.New("signature not detached")
	}

	return sd.verify(message)
}

func (sd *SignedData) verify(message []byte) error {
	if len(sd.psd.SignerInfos) == 0 {
		return errors.New("no signatures found")
	}

	certs, err := sd.psd.X509Certificates()
	if err != nil {
		return err
	}

	for _, si := range sd.psd.SignerInfos {
		var signedMessage []byte

		// SignedAttrs is optional if EncapContentInfo eContentType isn't id-data.
		if si.SignedAttrs == nil {
			// If SignedAttrs is absent, validate that EncapContentInfo eContentType
			// is id-data.
			if _, err := sd.psd.EncapContentInfo.DataEContent(); err != nil {
				return err
			}

			// If SignedAttrs is absent, the signature is over the original message
			// itself.
			signedMessage = message
		} else {
			// If SignedAttrs is present, we validate the mandatory ContentType and
			// MessageDigest attributes.
			siContentType, err := si.GetContentTypeAttribute()
			if err != nil {
				return err
			}

			if !siContentType.Equal(sd.psd.EncapContentInfo.EContentType) {
				return errors.New("invalid SignerInfo ContentType attribute")
			}

			// Calculate the digest over the actual message.
			hash := si.Hash()
			if hash == 0 {
				return fmt.Errorf("unknown digest algorithm: %s", si.DigestAlgorithm.Algorithm.String())
			}
			if !hash.Available() {
				return fmt.Errorf("Hash not avaialbe: %s", si.DigestAlgorithm.Algorithm.String())
			}
			actualMessageDigest := hash.New()
			if _, err = actualMessageDigest.Write(message); err != nil {
				return err
			}

			// Get the digest from the SignerInfo.
			messageDigestAttr, err := si.GetMessageDigestAttribute()
			if err != nil {
				return err
			}

			// Make sure message digests match.
			if !bytes.Equal(messageDigestAttr, actualMessageDigest.Sum(nil)) {
				return errors.New("invalid message digest")
			}

			// The signature is over the DER encoded signed attributes, minus the
			// leading class/tag/length bytes. This includes the digest of the
			// original message, so it is implicitly signed too.
			if signedMessage, err = si.SignedAttrs.MarshaledForSigning(); err != nil {
				return err
			}
		}

		cert, err := si.FindCertificate(certs)
		if err != nil {
			return err
		}

		algo := si.X509SignatureAlgorithm()
		if algo == x509.UnknownSignatureAlgorithm {
			return errors.New("unsupported signature or digest algorithm")
		}

		if err := cert.CheckSignature(algo, signedMessage, si.Signature); err != nil {
			return err
		}
	}

	// OK
	return nil
}
