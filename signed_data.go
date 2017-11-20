package cms

import "github.com/mastahyeti/cms/protocol"

// SignedData represents a signed message or detached signature.
type SignedData struct {
	psd protocol.SignedData
}

// ParseSignedData parses a SignedData from BER encoded data.
func ParseSignedData(ber []byte) (*SignedData, error) {
	ci, err := protocol.ParseContentInfo(ber)
	if err != nil {
		return nil, err
	}

	psd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}

	return &SignedData{psd}, nil
}

// GetData gets the encapsulated data from the SignedData. Nil will be returned
// if this is a detached signature. A protocol.ErrWrongType will be returned if
// the SignedData encapsulates something other than data (1.2.840.113549.1.7.1).
func (sd *SignedData) GetData() ([]byte, error) {
	return sd.psd.EncapContentInfo.DataEContent()
}
