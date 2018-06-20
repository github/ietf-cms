package cms

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/mastahyeti/cms/oid"
	"github.com/mastahyeti/cms/protocol"
	"github.com/mastahyeti/cms/timestamp"
	"github.com/mastahyeti/fakeca"
)

func TestAddTimestamps(t *testing.T) {
	// Good response
	tsa.Clear()
	sd, _ := NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		t.Fatal(err)
	}
	tsvs := sd.TimestampsVerifications()
	if len(tsvs) != 1 {
		t.Fatal("expected one signerinfo")
	}
	if _, err := tsvs[0].Verify(leaf.Certificate, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Error status in response
	tsa.HookResponse(func(resp timestamp.Response) timestamp.Response {
		resp.Status.Status = 1
		return resp
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		if _, isStatusErr := err.(timestamp.PKIStatusInfo); !isStatusErr {
			t.Fatalf("expected timestamp.PKIStatusInfo error, got %v", err)
		}
	}

	// Bad nonce
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Nonce.SetInt64(123123)
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != ErrTimestampMismatch {
		t.Fatalf("expected %v, got %v", ErrTimestampMismatch, err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != ErrTimestampMismatch {
		t.Fatalf("expected %v, got %v", ErrTimestampMismatch, err)
	}
}

func TestTimestampsVerifications(t *testing.T) {
	getTimestampedSignedData := func() *SignedData {
		sd, _ := NewSignedData([]byte("hi"))
		sd.Sign(leaf.Chain(), leaf.PrivateKey)
		tsReq, _ := tsRequest(sd.psd.SignerInfos[0])
		tsResp, _ := tsa.Do(tsReq)
		tsAttr, _ := protocol.NewAttribute(oid.AttributeTimeStampToken, tsResp.TimeStampToken)
		sd.psd.SignerInfos[0].UnsignedAttrs = append(sd.psd.SignerInfos[0].UnsignedAttrs, tsAttr)
		return sd
	}

	// Good timestamp
	tsa.Clear()
	sd := getTimestampedSignedData()
	tvs := sd.TimestampsVerifications()
	if len(tvs) != 1 {
		t.Fatal("expected 1 signerinfo")
	}
	if !tvs[0].getHasTimestamp() {
		t.Fatal("expected timestamp")
	}
	certs, err := tvs[0].Verify(leaf.Certificate, intermediateOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatal("expected 1 cert")
	}
	if !certs[0].Equal(tsa.ident.Certificate) {
		t.Fatal("expected tsa cert to be found")
	}

	// Timestamped maybe before not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//     |--------|
	//  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore
		return info
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != ErrTooOld {
		t.Fatalf("expected %v, got %v", ErrTooOld, err)
	}

	// Timestamped after not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//          |--------|
	//      sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore.Add(31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Timestamped maybe after not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                      |--------|
	//                                  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter
		return info
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != ErrTooNew {
		t.Fatalf("expected %v, got %v", ErrTooNew, err)
	}

	// Timestamped before not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                  |--------|
	//                              sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter.Add(-31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != ErrTimestampMismatch {
		t.Fatalf("expected %v, got %v", ErrTimestampMismatch, err)
	}

	// Untrusted signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		badIdent := fakeca.New()
		tst.SignerInfos = nil
		tst.AddSignerInfo(badIdent.Chain(), badIdent.PrivateKey)
		return tst
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); !ok {
			t.Fatalf("expected UnknownAuthorityError, got %v", err)
		}
	}

	// Bad signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		tst.SignerInfos[0].Signature[0] ^= 0xFF
		return tst
	})
	sd = getTimestampedSignedData()
	tvs = sd.TimestampsVerifications()
	if _, err = tvs[0].Verify(leaf.Certificate, intermediateOpts); err != rsa.ErrVerification {
		t.Fatalf("expected %v, got %v", rsa.ErrVerification, err)
	}
}
