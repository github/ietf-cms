// Package pkcs7 implements parsing and generation of some PKCS#7 structures.
package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	_ "crypto/sha1" // for crypto.SHA1
)

var (
	// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
	// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
	// and Enveloped Data are supported (1.2.840.113549.1.7.3)
	ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

	// ErrWrongType is returned by methods that make assumptions about types.
	// Helper methods are defined for accessing CHOICE and  ANY feilds. These
	// helper methods get the value of the field, assuming it is of a given type.
	// This error is returned if that assumption is wrong and the field has a
	// different type.
	ErrWrongType = errors.New("pkcs7: wrong choice or any type")
)

var (
	// Content type OIDs
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// Attribute OIDs
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedDataContent gets the content assuming contentType is signedData.
func (ci contentInfo) signedDataContent() (sd signedData, err error) {
	if !ci.ContentType.Equal(oidSignedData) {
		err = ErrWrongType
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return
	}
	if len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// dataEContent gets the EContent assuming EContentType is data. A nil byte
// slice is returned if the OPTIONAL eContent field is missing.
func (eci encapsulatedContentInfo) dataEContent() ([]byte, error) {
	if !eci.EContentType.Equal(oidData) {
		return nil, ErrWrongType
	}

	return eci.EContent.Bytes, nil
}

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }
//
// AttributeValue ::= ANY
type attribute struct {
	Type asn1.ObjectIdentifier

	// This should be a SET OF ANY, but Go's asn1 parser can't handle slices of
	// RawValues. Use value() to get an AnySet of the value.
	RawValue asn1.RawValue
}

// value further decodes the attribute value as a SET OF ANY, which Go's asn1
// parser can't handle directly.
func (a attribute) value() (anySet, error) {
	return decodeAnySet(a.RawValue)
}

// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type attributes []attribute

// getOnlyAttributeValueBytes gets an attribute value, returning an error if the
// attribute occurs multiple times or have multiple values.
func (attrs attributes) getOnlyAttributeValueBytes(oid asn1.ObjectIdentifier) (rv asn1.RawValue, err error) {
	var vals []anySet
	if vals, err = attrs.getValues(oid); err != nil {
		return
	}
	if len(vals) != 1 {
		err = fmt.Errorf("expected 1 attribute found %d", len(vals))
		return
	}
	if len(vals[0].Elements) != 1 {
		err = fmt.Errorf("expected 1 attribute value found %d", len(vals[0].Elements))
		return
	}

	return vals[0].Elements[0], nil
}

// get retreives the attributes with the given OID. A nil value is returned if
// the OPTIONAL SET of Attributes is missing from the SignerInfo. An empty slice
// is returned if the specified attribute isn't in the set.
func (attrs attributes) getValues(oid asn1.ObjectIdentifier) ([]anySet, error) {
	if attrs == nil {
		return nil, nil
	}

	vals := []anySet{}
	for _, attr := range attrs {
		if attr.Type.Equal(oid) {
			val, err := attr.value()
			if err != nil {
				return nil, err
			}

			vals = append(vals, val)
		}
	}

	return vals, nil
}

// IssuerAndSerialNumber ::= SEQUENCE {
// 	issuer Name,
// 	serialNumber CertificateSerialNumber }
//
// CertificateSerialNumber ::= INTEGER
type issuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber int
}

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignatureValue ::= OCTET STRING
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      attributes `asn1:"set,optional,tag:1"`
}

// issuerAndSerialNumberSID gets the SID, assuming it is a issuerAndSerialNumber.
func (si signerInfo) issuerAndSerialNumberSID() (isn issuerAndSerialNumber, err error) {
	if si.SID.Class != asn1.ClassUniversal || si.SID.Tag != asn1.TagSequence {
		err = ErrWrongType
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(si.SID.FullBytes, &isn); err == nil && len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}

// subjectKeyIdentifierSID gets the SID, assuming it is a subjectKeyIdentifier.
func (si signerInfo) subjectKeyIdentifierSID() ([]byte, error) {
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 {
		return nil, ErrWrongType
	}

	return si.SID.Bytes, nil
}

// getContentTypeAttribute gets the signed ContentType attribute from the
// SignerInfo.
func (si signerInfo) getContentTypeAttribute() (asn1.ObjectIdentifier, error) {
	rv, err := si.SignedAttrs.getOnlyAttributeValueBytes(oidAttributeContentType)
	if err != nil {
		return nil, err
	}

	var ct asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(rv.FullBytes, &ct); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("unexpected trailing data")
	}

	return ct, nil
}

// getMessageDigestAttribute gets the signed MessageDigest attribute from the
// SignerInfo.
func (si signerInfo) getMessageDigestAttribute() ([]byte, error) {
	rv, err := si.SignedAttrs.getOnlyAttributeValueBytes(oidAttributeMessageDigest)
	if err != nil {
		return nil, err
	}
	if rv.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected class %d, got %d", asn1.ClassUniversal, rv.Class)
	}
	if rv.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("expected tag %d, got %d", asn1.TagOctetString, rv.Tag)
	}

	return rv.Bytes, nil
}

// getSigningTimeAttribute gets the signed SigningTime attribute from the
// SignerInfo.
func (si signerInfo) getSigningTimeAttribute() (time.Time, error) {
	var t time.Time

	rv, err := si.SignedAttrs.getOnlyAttributeValueBytes(oidAttributeSigningTime)
	if err != nil {
		return t, err
	}
	if rv.Class != asn1.ClassUniversal {
		return t, fmt.Errorf("expected class %d, got %d", asn1.ClassUniversal, rv.Class)
	}
	if rv.Tag != asn1.TagUTCTime && rv.Tag != asn1.TagGeneralizedTime {
		return t, fmt.Errorf("expected tag %d or %d, got %d", asn1.TagUTCTime, asn1.TagGeneralizedTime, rv.Tag)
	}

	if rest, err := asn1.Unmarshal(rv.FullBytes, &t); err != nil {
		return t, err
	} else if len(rest) > 0 {
		return t, errors.New("unexpected trailing data")
	}

	return t, nil
}

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
//
// CertificateSet ::= SET OF CertificateChoices
//
// CertificateChoices ::= CHOICE {
//   certificate Certificate,
//   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
//   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
//   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//   other [3] IMPLICIT OtherCertificateFormat }
//
// OtherCertificateFormat ::= SEQUENCE {
//   otherCertFormat OBJECT IDENTIFIER,
//   otherCert ANY DEFINED BY otherCertFormat }
//
// RevocationInfoChoices ::= SET OF RevocationInfoChoice
//
// RevocationInfoChoice ::= CHOICE {
//   crl CertificateList,
//   other [1] IMPLICIT OtherRevocationInfoFormat }
//
// OtherRevocationInfoFormat ::= SEQUENCE {
//   otherRevInfoFormat OBJECT IDENTIFIER,
//   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
//
// SignerInfos ::= SET OF SignerInfo
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

// x509Certificates gets the certificates, assuming that they're X.509 encoded.
func (sd signedData) x509Certificates() ([]*x509.Certificate, error) {
	// Certificates field is optional. Handle missing value.
	if sd.Certificates == nil {
		return nil, nil
	}

	// Empty set
	if len(sd.Certificates) == 0 {
		return []*x509.Certificate{}, nil
	}

	certs := make([]*x509.Certificate, 0, len(sd.Certificates))
	for _, raw := range sd.Certificates {
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("Unsupported certificate type (class %d, tag %d)", raw.Class, raw.Tag)
		}

		x509, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, x509)
	}

	return certs, nil
}

// ParseContentInfo parses a top-level CMS ContentInfo packet.
func ParseContentInfo(ber []byte) (ci contentInfo, err error) {
	var der []byte
	if der, err = ber2der(ber); err != nil {
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(der, &ci); err != nil {
		return
	}
	if len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}
