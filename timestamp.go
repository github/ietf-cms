package cms

import (
	"bytes"

	"github.com/mastahyeti/cms/oid"
	"github.com/mastahyeti/cms/protocol"
	"github.com/mastahyeti/cms/timestamp"
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

	hash, err := si.Hash()
	if err != nil {
		return nilAttr, err
	}

	req, err := timestamp.NewRequest(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return nilAttr, err
	}

	resp, err := req.Do(url)
	if err != nil {
		return nilAttr, err
	}

	return protocol.NewAttribute(oid.AttributeTimeStampToken, resp.TimeStampToken)
}
