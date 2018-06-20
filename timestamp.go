package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/mastahyeti/cms/oid"
	"github.com/mastahyeti/cms/protocol"
	"github.com/mastahyeti/cms/timestamp"
)

var (
	// ErrNoTimestamp is returned by *TimestampVerification.Verify() if the
	// SignerInfo didn't contain a timestamp attribute.
	ErrNoTimestamp = errors.New("no timestamp")

	// ErrTooOld is returned by *TimestampVerification.Verify() if the timestamp
	// was created before the timestampedSignatureCert's not-before date.
	ErrTooOld = errors.New("timestamp before certificate's not-before date")

	// ErrTooNew is returned by *TimestampVerification.Verify() if the timestamp
	// was created after the timestampedSignatureCert's not-after date.
	ErrTooNew = errors.New("timestamp after certificate's not-after date")

	// ErrTimestampMismatch is returned when a timestamp response contains the wrong
	// message imprint or when a timestamp's message imprint doesn't match the
	// content its a timestamp of.
	ErrTimestampMismatch = errors.New("invalid message imprint")
)

// AddTimestamps adds a timestamp to the SignedData using the RFC3161
// timestamping service at the given URL. This timestamp proves that the signed
// message existed the time of generation, allowing verifiers to have more trust
// in old messages signed with revoked keys.
func (sd *SignedData) AddTimestamps(url string) error {
	var (
		attrs = make([]protocol.Attribute, len(sd.psd.SignerInfos))
		err   error
	)

	// Fetch all timestamp tokens before adding any to sd. This avoids a partial
	// failure.
	for i := range attrs {
		if attrs[i], err = fetchTS(url, sd.psd.SignerInfos[i]); err != nil {
			return err
		}
	}

	for i := range attrs {
		sd.psd.SignerInfos[i].UnsignedAttrs = append(sd.psd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}

func fetchTS(url string, si protocol.SignerInfo) (protocol.Attribute, error) {
	nilAttr := protocol.Attribute{}

	req, err := tsRequest(si)
	if err != nil {
		return nilAttr, err
	}

	resp, err := req.Do(url)
	if err != nil {
		return nilAttr, err
	}

	if tsti, err := resp.Info(); err != nil {
		return nilAttr, err
	} else if !req.Matches(tsti) {
		return nilAttr, ErrTimestampMismatch
	}

	return protocol.NewAttribute(oid.AttributeTimeStampToken, resp.TimeStampToken)
}

func tsRequest(si protocol.SignerInfo) (timestamp.Request, error) {
	hash, err := si.Hash()
	if err != nil {
		return timestamp.Request{}, err
	}

	mi, err := timestamp.NewMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return timestamp.Request{}, err
	}

	return timestamp.Request{
		Version:        1,
		CertReq:        true,
		Nonce:          timestamp.GenerateNonce(),
		MessageImprint: mi,
	}, nil
}

// TimestampVerification is the timestamp verification status for a single
// signature on a SignedData.
type TimestampVerification struct {
	si protocol.SignerInfo

	_err                error
	_timestampTokenInfo *timestamp.Info
	_timestampToken     **SignedData
	_hasTimestamp       *bool
}

// TimestampsVerifications gets a slice of TimestampVerification structs which
// give information about the timestamps, if any, attached to signatures.
func (sd *SignedData) TimestampsVerifications() []*TimestampVerification {
	verifications := make([]*TimestampVerification, 0, len(sd.psd.SignerInfos))

	for _, si := range sd.psd.SignerInfos {
		verifications = append(verifications, &TimestampVerification{si: si})
	}

	return verifications
}

// Verify checks that the timestamp is genuine and that its value falls within
// the not-before and not-after dates specified in timestampedSignatureCert.
// Possible error values include ErrNoTimestamp, ErrTooOld and ErrTooNew, though
// other errors may be returned for defects in the timestamp attribute. Each
// timestamp signature's associated certificate is verified using the provided
// roots. UnsafeNoVerify may be specified to skip this verification. Nil may be
// provided to use system roots. The certificates whose keys made the signatures
// are returned.
func (tv *TimestampVerification) Verify(timestampedSignatureCert *x509.Certificate, roots *x509.CertPool) ([]*x509.Certificate, error) {
	hasTS := tv.getHasTimestamp()
	tst := tv.getTimestampToken()
	tsti := tv.getTimestampTokenInfo()
	if tv._err != nil {
		return nil, tv._err
	}
	if !hasTS {
		return nil, ErrNoTimestamp
	}
	if tsti.Version != 1 {
		return nil, protocol.ErrUnsupported
	}

	// verify timestamp signature and certificate chain..
	certs, err := tst.Verify(roots)
	if err != nil {
		return nil, err
	}

	// verify timestamp token matches SignerInfo.
	hash, err := tsti.MessageImprint.Hash()
	if err != nil {
		return nil, err
	}
	mi, err := timestamp.NewMessageImprint(hash, bytes.NewReader(tv.si.Signature))
	if err != nil {
		return nil, err
	}
	if !mi.Equal(tsti.MessageImprint) {
		return nil, ErrTimestampMismatch
	}

	// verify timestamp is within appropriate range.
	if !tsti.Before(timestampedSignatureCert.NotAfter) {
		return nil, ErrTooNew
	}
	if !tsti.After(timestampedSignatureCert.NotBefore) {
		return nil, ErrTooOld
	}

	return certs, nil
}

func (tv *TimestampVerification) getHasTimestamp() bool {
	if tv._hasTimestamp != nil {
		return *tv._hasTimestamp
	}

	if tv._err != nil {
		return false
	}

	var vals []protocol.AnySet
	if vals, tv._err = tv.si.UnsignedAttrs.GetValues(oid.AttributeTimeStampToken); tv._err != nil {
		return false
	}

	hasTS := len(vals) > 0
	tv._hasTimestamp = &hasTS
	return hasTS
}

func (tv *TimestampVerification) getTimestampToken() *SignedData {
	if tv._timestampToken != nil {
		return *tv._timestampToken
	}

	hasTS := tv.getHasTimestamp()
	if tv._err != nil {
		return nil
	}

	var tst *SignedData

	if hasTS {
		var rv asn1.RawValue
		if rv, tv._err = tv.si.UnsignedAttrs.GetOnlyAttributeValueBytes(oid.AttributeTimeStampToken); tv._err != nil {
			return nil
		}

		if tst, tv._err = ParseSignedData(rv.FullBytes); tv._err != nil {
			return nil
		}
	}

	tv._timestampToken = &tst
	return tst
}

func (tv *TimestampVerification) getTimestampTokenInfo() timestamp.Info {
	if tv._timestampTokenInfo != nil {
		return *tv._timestampTokenInfo
	}

	// zero value of timestamp.Info. We return this on error.
	var zeroTSTI timestamp.Info

	hasTS := tv.getHasTimestamp()
	tst := tv.getTimestampToken()
	if tv._err != nil {
		return zeroTSTI
	}

	var tsti timestamp.Info

	if hasTS && tst != nil {
		if tsti, tv._err = timestamp.ParseInfo(tst.psd.EncapContentInfo); tv._err != nil {
			return zeroTSTI
		}
	}

	tv._timestampTokenInfo = &tsti
	return tsti
}
