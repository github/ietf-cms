package protocol

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

// TimeStampReq ::= SEQUENCE  {
// 	version                      INTEGER  { v1(1) },
// 	messageImprint               MessageImprint,
// 		--a hash algorithm OID and the hash value of the data to be
// 		--time-stamped
// 	reqPolicy             TSAPolicyId              OPTIONAL,
// 	nonce                 INTEGER                  OPTIONAL,
// 	certReq               BOOLEAN                  DEFAULT FALSE,
// 	extensions            [0] IMPLICIT Extensions  OPTIONAL  }
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"tag:1,optional"`
}

const nonceBytes = 16

// GenerateNonce generates a new nonce for this TSR.
func (tsr *TimeStampReq) GenerateNonce() {
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	if tsr.Nonce == nil {
		tsr.Nonce = new(big.Int)
	}

	tsr.Nonce.SetBytes(buf[:])
}

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
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// GenTimeMax is the latest time at which the token could have been generated
// based on the included GenTime and Accuracy attributes.
func (tsti *TSTInfo) GenTimeMax() time.Time {
	return tsti.GenTime.Add(tsti.Accuracy.Duration())
}

// GenTimeMin is the earliest time at which the token could have been generated
// based on the included GenTime and Accuracy attributes.
func (tsti *TSTInfo) GenTimeMin() time.Time {
	return tsti.GenTime.Add(-tsti.Accuracy.Duration())
}

// MessageImprint ::= SEQUENCE  {
//   hashAlgorithm                AlgorithmIdentifier,
//   hashedMessage                OCTET STRING  }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// NewMessageImprint creates a new MessageImprint, digesting all bytes from the
// provided reader using the specified hash.
func NewMessageImprint(hash crypto.Hash, r io.Reader) (MessageImprint, error) {
	digestAlgorithm := hashToDigestAlgorithm[hash]
	if len(digestAlgorithm) == 0 {
		return MessageImprint{}, fmt.Errorf("Unsupported hash algorithm: %d", hash)
	}

	if !hash.Available() {
		return MessageImprint{}, fmt.Errorf("Hash not avaialbe: %d", hash)
	}
	h := hash.New()
	if _, err := io.Copy(h, r); err != nil {
		return MessageImprint{}, err
	}

	return MessageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestAlgorithm},
		HashedMessage: h.Sum(nil),
	}, nil
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

// Equal checks if this MessageImprint is identical to another MessageImprint.
func (mi MessageImprint) Equal(other MessageImprint) bool {
	if !mi.HashAlgorithm.Algorithm.Equal(other.HashAlgorithm.Algorithm) {
		return false
	}
	if len(mi.HashAlgorithm.Parameters.Bytes) > 0 || len(other.HashAlgorithm.Parameters.Bytes) > 0 {
		if !bytes.Equal(mi.HashAlgorithm.Parameters.FullBytes, other.HashAlgorithm.Parameters.FullBytes) {
			return false
		}
	}
	if !bytes.Equal(mi.HashedMessage, other.HashedMessage) {
		return false
	}
	return true
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

// Duration returns this Accuracy as a time.Duration.
func (a Accuracy) Duration() time.Duration {
	return 0 +
		time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}
