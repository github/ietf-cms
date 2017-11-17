package pkcs7

import (
	"encoding/asn1"
	"fmt"
)

// anySet is a helper for dealing with SET OF ANY types.
type anySet struct {
	Elements []asn1.RawValue `asn1:"set"`
}

// decodeAnySet manually decodes a SET OF ANY type, since Go's parser can't
// handle them.
func decodeAnySet(rv asn1.RawValue) (as anySet, err error) {
	// Make sure it's really a SET.
	if rv.Class != asn1.ClassUniversal {
		err = fmt.Errorf("Bad class. Expecting %d, got %d", asn1.ClassUniversal, rv.Class)
		return
	}
	if rv.Tag != asn1.TagSet {
		err = fmt.Errorf("Bad tag. Expecting %d, got %d", asn1.TagSet, rv.Tag)
		return
	}

	// Decode each element.
	der := rv.Bytes
	for len(der) > 0 {
		if der, err = asn1.Unmarshal(der, &rv); err != nil {
			return
		}

		as.Elements = append(as.Elements, rv)
	}

	return
}

// encode manually encodes a SET OF ANY type, since Go's parser can't handle
// them.
func (as anySet) encode(dst *asn1.RawValue) (err error) {
	dst.Class = asn1.ClassUniversal
	dst.Tag = asn1.TagSet
	dst.IsCompound = true

	var der []byte
	for _, elt := range as.Elements {
		if der, err = asn1.Marshal(elt); err != nil {
			return
		}

		dst.Bytes = append(dst.Bytes, der...)
	}

	dst.FullBytes, err = asn1.Marshal(*dst)

	return
}
