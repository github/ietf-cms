package protocol

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func TestTimeStampReq(t *testing.T) {
	tsr := new(TimeStampReq)

	tsr.GenerateNonce()
	if tsr.Nonce == nil {
		t.Fatal("expected non-nil nonce")
	}
	// don't check for exact bitlength match, since leading 0's don't count
	// towards length.
	if tsr.Nonce.BitLen() < nonceBytes*8/2 {
		t.Fatalf("expected %d bit nonce, got %d", nonceBytes*8, tsr.Nonce.BitLen())
	}
	if tsr.Nonce.Cmp(new(big.Int)) == 0 {
		t.Fatal("expected non-zero nonce")
	}
}

func TestMessageImprint(t *testing.T) {
	m := []byte("hello, world!")
	mi1, err := NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}

	// same
	mi2, err := NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// round trip
	der, err := asn1.Marshal(mi1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = asn1.Unmarshal(der, &mi2); err != nil {
		t.Fatal(err)
	}
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// null value for hash alrogithm parameters (as opposed to being absent entirely)
	mi2, _ = NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	mi2.HashAlgorithm.Parameters = asn1.NullRawValue
	if !mi1.Equal(mi2) {
		t.Fatal("expected m1==m2")
	}

	// different digest
	mi2, err = NewMessageImprint(crypto.SHA1, bytes.NewReader(m))
	if err != nil {
		panic(err)
	}
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}

	// different message
	mi2, err = NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("wrong")))
	if err != nil {
		panic(err)
	}
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}

	// bad digest
	mi2, _ = NewMessageImprint(crypto.SHA256, bytes.NewReader(m))
	mi2.HashedMessage = mi2.HashedMessage[0 : len(mi2.HashedMessage)-1]
	if mi1.Equal(mi2) {
		t.Fatal("expected m1!=m2")
	}
}

func TestTSTInfo(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureTimestampSymantecWithCerts)
	sd, _ := ci.SignedDataContent()
	tsti, _ := sd.EncapContentInfo.TSTInfoEContent()

	expectedVersion := 1
	if tsti.Version != expectedVersion {
		t.Fatalf("expected version %d, got %d", expectedVersion, tsti.Version)
	}

	expectedPolicy := asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 3}
	if !tsti.Policy.Equal(expectedPolicy) {
		t.Fatalf("expected policy %s, got %s", expectedPolicy.String(), tsti.Policy.String())
	}

	expectedHash := crypto.SHA256
	if hash, err := tsti.MessageImprint.Hash(); err != nil {
		t.Fatal(err)
	} else if hash != expectedHash {
		t.Fatalf("expected hash %d, got %d", expectedHash, hash)
	}

	expectedMI, _ := NewMessageImprint(crypto.SHA256, bytes.NewReader([]byte("hello\n")))
	if !tsti.MessageImprint.Equal(expectedMI) {
		t.Fatalf("expected hash %s, got %s",
			hex.EncodeToString(expectedMI.HashedMessage),
			hex.EncodeToString(tsti.MessageImprint.HashedMessage))
	}

	expectedSN := new(big.Int).SetBytes([]byte{0x34, 0x99, 0xB7, 0x2E, 0xCE, 0x6F, 0xB6, 0x6B, 0x68, 0x2D, 0x35, 0x25, 0xC6, 0xE5, 0x6A, 0x07, 0x77, 0x3D, 0xC9, 0xD8})
	if tsti.SerialNumber.Cmp(expectedSN) != 0 {
		t.Fatalf("expected SN %s, got %s", expectedSN.String(), tsti.SerialNumber.String())
	}

	timeFmt := "2006-01-02 15:04:05 MST"
	expectedGenTime, _ := time.Parse(timeFmt, "2018-05-09 18:25:22 UTC")
	if !tsti.GenTime.Equal(expectedGenTime) {
		t.Fatalf("expected gentime %s, got %s", expectedGenTime.String(), tsti.GenTime.String())
	}

	expectedAccuracy := 30 * time.Second
	if accuracy := tsti.Accuracy.Duration(); accuracy != expectedAccuracy {
		t.Fatalf("expected accurracy %s, got %s", expectedAccuracy.String(), accuracy.String())
	}

	expectedGenTimeMax := expectedGenTime.Add(expectedAccuracy)
	if tsti.GenTimeMax() != expectedGenTimeMax {
		t.Fatalf("expected gentimemax %s, got %s", expectedGenTimeMax.String(), tsti.GenTimeMax().String())
	}

	expectedGenTimeMin := expectedGenTime.Add(-expectedAccuracy)
	if tsti.GenTimeMin() != expectedGenTimeMin {
		t.Fatalf("expected gentimemax %s, got %s", expectedGenTimeMin.String(), tsti.GenTimeMin().String())
	}

	expectedOrdering := false
	if tsti.Ordering != expectedOrdering {
		t.Fatalf("expected ordering %t, got %t", expectedOrdering, tsti.Ordering)
	}

	if tsti.Nonce != nil {
		t.Fatal("expected nil nonce")
	}

	// don't bother with TSA, since we don't want to mess with parsing GeneralNames.

	if tsti.Extensions != nil {
		t.Fatal("expected nil extensions")
	}
}
