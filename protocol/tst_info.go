package protocol

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// TSTInfo ::= SEQUENCE  {
//   version                      INTEGER  { v1(1) },
//   policy                       TSAPolicyId,
//   messageImprint               MessageImprint,
//     -- MUST have the same value as the similar field in
//     -- TimeStampReq
//   serialNumber                 INTEGER,
//     -- Time-Stamping users MUST be ready to accommodate integers
//     -- up to 160 bits.
//   genTime                      GeneralizedTime,
//   accuracy                     Accuracy                 OPTIONAL,
//   ordering                     BOOLEAN             DEFAULT FALSE,
//   nonce                        INTEGER                  OPTIONAL,
//     -- MUST be present if the similar field was present
//     -- in TimeStampReq.  In that case it MUST have the same value.
//   tsa                          [0] GeneralName          OPTIONAL,
//   extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
//
// TSAPolicyId ::= OBJECT IDENTIFIER
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          int              `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// MessageImprint ::= SEQUENCE  {
//   hashAlgorithm                AlgorithmIdentifier,
//   hashedMessage                OCTET STRING  }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// Hash gets the crypto.Hash associated with this SignerInfo's DigestAlgorithm.
// 0 is returned for unrecognized algorithms.
func (mi MessageImprint) Hash() (crypto.Hash, error) {
	algo := mi.HashAlgorithm.Algorithm.String()
	hash := digestAlgorithmToHash[algo]
	if hash == 0 {
		return 0, fmt.Errorf("unknown digest algorithm: %s", algo)
	}
	if !hash.Available() {
		return 0, fmt.Errorf("Hash not avaialbe: %s", algo)
	}

	return hash, nil
}

// Accuracy ::= SEQUENCE {
//   seconds        INTEGER              OPTIONAL,
//   millis     [0] INTEGER  (1..999)    OPTIONAL,
//   micros     [1] INTEGER  (1..999)    OPTIONAL  }
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}
