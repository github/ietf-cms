package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pkcs12"
)

func TestSignerInfo(t *testing.T) {
	priv, cert, err := pkcs12.Decode(fixturePFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello, world!")

	eci, err := NewEncapsulatedContentInfo(msg, oidData)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := NewSignedData(eci)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{cert}
	if err = sd.AddSignerInfo(chain, priv.(*ecdsa.PrivateKey)); err != nil {
		t.Fatal(err)
	}

	der, err := sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}

	ci, err := ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := sd2.EncapContentInfo.DataEContent()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Fatal()
	}

	// Make detached
	sd.EncapContentInfo.EContent = asn1.RawValue{}

	der, err = sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}

	ci, err = ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err = ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err = sd2.EncapContentInfo.DataEContent()
	if err != nil {
		t.Fatal(err)
	}
	if msg2 != nil {
		t.Fatal()
	}
}

func TestEncapsulatedContentInfo(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	oldECI := sd.EncapContentInfo

	oldData, err := oldECI.DataEContent()
	if err != nil {
		t.Fatal(err)
	}

	newECI, err := NewEncapsulatedContentInfo(oldData, oidData)
	if err != nil {
		t.Fatal(err)
	}

	newData, err := newECI.DataEContent()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldData, newData) {
		t.Fatal("ECI data round trip mismatch: ", oldData, " != ", newData)
	}

	oldDER, err := asn1.Marshal(oldECI)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newECI)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("ECI round trip mismatch: ", oldDER, " != ", newDER)
	}
}

func TestMessageDigestAttribute(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]

	oldAttrVal, err := si.GetMessageDigestAttribute()
	if err != nil {
		t.Fatal(err)
	}

	var oldAttr Attribute
	for _, attr := range si.SignedAttrs {
		if attr.Type.Equal(oidAttributeMessageDigest) {
			oldAttr = attr
			break
		}
	}

	newAttr, err := NewAttribute(oidAttributeMessageDigest, oldAttrVal)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldAttr.RawValue.Bytes, newAttr.RawValue.Bytes) {
		t.Fatal("raw value mismatch")
	}

	oldDER, err := asn1.Marshal(oldAttr)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newAttr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("der mismatch")
	}
}

func TestContentTypeAttribute(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]

	oldAttrVal, err := si.GetContentTypeAttribute()
	if err != nil {
		t.Fatal(err)
	}

	var oldAttr Attribute
	for _, attr := range si.SignedAttrs {
		if attr.Type.Equal(oidAttributeContentType) {
			oldAttr = attr
			break
		}
	}

	newAttr, err := NewAttribute(oidAttributeContentType, oldAttrVal)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldAttr.RawValue.Bytes, newAttr.RawValue.Bytes) {
		t.Fatal("raw value mismatch")
	}

	oldDER, err := asn1.Marshal(oldAttr)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newAttr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("der mismatch")
	}
}

func TestIssuerAndSerialNumber(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]
	certs, _ := sd.X509Certificates()
	cert, _ := si.FindCertificate(certs)

	newISN, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		t.Fatal(err)
	}

	oldDER, _ := asn1.Marshal(si.SID)
	newDER, _ := asn1.Marshal(newISN)

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("SID mismatch")
	}
}

func TestParseSignatureOne(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOne)
}

func TestParseSignatureGPGSMAttached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureGPGSMAttached)
}

func TestParseSignatureGPGSM(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureGPGSM)
}

func TestParseSignatureNoCertsGPGSM(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureNoCertsGPGSM)
}

func TestParseSignatureOpenSSLAttached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOpenSSLAttached)
}

func TestParseSignatureOpenSSLDetached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOpenSSLDetached)
}

func TestParseSignautreOutlookDetached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOutlookDetached)
}

func TestParseTimestampSymantec(t *testing.T) {
	testParseContentInfo(t, fixtureTimestampSymantec)
}

func TestParseTimestampSymantecWithCerts(t *testing.T) {
	testParseContentInfo(t, fixtureTimestampSymantecWithCerts)
}

func TestParseTimestampDigicert(t *testing.T) {
	testParseContentInfo(t, fixtureTimestampDigicert)
}

func TestParseTimestampComodo(t *testing.T) {
	testParseContentInfo(t, fixtureTimestampComodo)
}

func TestParseTimestampGlobalSign(t *testing.T) {
	testParseContentInfo(t, fixtureTimestampGlobalSign)
}

func testParseContentInfo(t *testing.T, ber []byte) {
	ci, err := ParseContentInfo(ber)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}

	if sd.EncapContentInfo.IsTypeData() {
		if !sd.EncapContentInfo.EContentType.Equal(oidData) {
			t.Fatalf("expected %s content, got %s", oidData.String(), sd.EncapContentInfo.EContentType.String())
		}

		data, err := sd.EncapContentInfo.DataEContent()
		if err != nil {
			t.Fatal(err)
		}
		if data != nil && len(data) == 0 {
			t.Fatal("attached signature with zero length data")
		}
	} else if sd.EncapContentInfo.IsTypeTSTInfo() {
		if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
			t.Fatalf("expected %s content, got %s", oidTSTInfo.String(), sd.EncapContentInfo.EContentType.String())
		}

		tsti, err := sd.EncapContentInfo.TSTInfoEContent()
		if err != nil {
			t.Fatal(err)
		}

		hash, err := tsti.MessageImprint.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if hash != crypto.SHA256 {
			t.Fatalf("expected SHA256 hash, found %s", tsti.MessageImprint.HashAlgorithm.Algorithm.String())
		}

		if tsti.SerialNumber == nil {
			t.Fatal("expected non-nill SN")
		}
		if tsti.SerialNumber.Cmp(big.NewInt(0)) <= 0 {
			t.Fatal("expected SN>0")
		}

		if tsti.Version != 1 {
			t.Fatalf("expected tst v1, found %d", tsti.Version)
		}
	} else {
		t.Fatalf("unknown econtenttype: %s", sd.EncapContentInfo.EContentType.String())
	}

	for _, si := range sd.SignerInfos {
		if _, err = si.FindCertificate(certs); err != nil && len(certs) > 0 {
			t.Fatal(err)
		}

		if ct, errr := si.GetContentTypeAttribute(); errr != nil {
			t.Fatal(errr)
		} else {
			// signerInfo contentType attribute must match signedData
			// encapsulatedContentInfo content type.
			if !ct.Equal(sd.EncapContentInfo.EContentType) {
				t.Fatalf("expected %s content, got %s", sd.EncapContentInfo.EContentType.String(), ct.String())
			}
		}

		if md, errr := si.GetMessageDigestAttribute(); errr != nil {
			t.Fatal(errr)
		} else if len(md) == 0 {
			t.Fatal("nil/empty message digest attribute")
		}

		if algo := si.X509SignatureAlgorithm(); algo == x509.UnknownSignatureAlgorithm {
			t.Fatalf("unknown signature algorithm")
		}

		var nilTime time.Time
		if st, errr := si.GetSigningTimeAttribute(); errr != nil {
			t.Fatal(errr)
		} else if st == nilTime {
			t.Fatal("0 value signing time")
		}
	}

	// round trip contentInfo
	der, err := ber2der(ber)
	if err != nil {
		t.Fatal(err)
	}

	der2, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded contentInfo doesn't match original")
	}

	// round trip signedData
	der = ci.Content.Bytes

	der2, err = asn1.Marshal(*sd)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded signedData doesn't match original")
	}
}

var fixtureSignatureOne = mustBase64Decode("" +
	"MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B" +
	"BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG" +
	"SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh" +
	"cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB" +
	"Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw" +
	"gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP" +
	"J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF" +
	"a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw" +
	"DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8" +
	"zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+" +
	"L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy" +
	"axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD" +
	"bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI" +
	"hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4" +
	"LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG" +
	"SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX" +
	"iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM" +
	"FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS",
)

var fixtureSignatureGPGSMAttached = mustBase64Decode("" +
	"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" +
	"SDXMwnexRO3w39tu4ChUFbsX8l5CAAAAAAAA",
)

var fixtureSignatureGPGSM = mustBase64Decode("" +
	"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" +
	"SX+du6QAAAAAAAA=",
)

var fixtureSignatureNoCertsGPGSM = mustBase64Decode("" +
	"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B" +
	"BwEAADGCAeEwggHdAgEBMCAwFDESMBAGA1UEAxMJQmVuIFRvZXdzAggWdNrn7G+u" +
	"SDANBglghkgBZQMEAgEFAKCBkzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG" +
	"CSqGSIb3DQEJBTEPFw0xNzExMTcwMDQxNDhaMCgGCSqGSIb3DQEJDzEbMBkwCwYJ" +
	"YIZIAWUDBAECMAoGCCqGSIb3DQMHMC8GCSqGSIb3DQEJBDEiBCBNyg/V9CSjGwOr" +
	"gHy6536zK/LQie7RzuFUs6/tRY3g3DANBgkqhkiG9w0BAQEFAASCAQAvGAGPMaH3" +
	"oRiNDU0AGIVyjXUrZ8g2VRazGCTuuO0CPGWBDbBuuvCePuWTddcv5KHHyrYO0yUD" +
	"xergVhh1EXIsOItHbJ6QeMstmY8Ub7HGm4Srdtm3MMSEe24zRmKK5yvPfeaaXeb6" +
	"MASKXvViU/j9VDwUZ2CFPUzPq8DlS6j4w6dapfphFGN1wJV3ADLUzUkTXfXQ57HE" +
	"WUKdbxgcuyBH7eLhZpKAXP31iRKm2b7dV50SruRCqNYZOp8bUQ57bC2jels0dzQd" +
	"EQS76O/DH6eQ3/OgvpmR8BjlujA82tgjqP7fj0S7Cw2VlPqcey0iqRmAmiO2qzOI" +
	"KAYzMkxWr7iUAAAAAAAA",
)

var fixtureSignatureOpenSSLAttached = mustBase64Decode("" +
	"MIIFGgYJKoZIhvcNAQcCoIIFCzCCBQcCAQExDzANBglghkgBZQMEAgEFADAcBgkq" +
	"hkiG9w0BBwGgDwQNaGVsbG8sIHdvcmxkIaCCAqMwggKfMIIBh6ADAgECAgEAMA0G" +
	"CSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCGNtcy10ZXN0MB4XDTE3MTEyMDIwNTM0" +
	"M1oXDTI3MTExODIwNTM0M1owEzERMA8GA1UEAwwIY21zLXRlc3QwggEiMA0GCSqG" +
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWMRnJdRQxw8j8Yn3jh/rcZyeALStl+MmM" +
	"TEtr6XsmMOWQhnP6nCAIOw5EIAXGpKl4Yg3F2gDKmJCVl279Q+G9nLtvmWvCzu19" +
	"BJUG7jVLWzO8KSuJa83iiilZUP2adVZujdGB6dxekIBu7vkYi9XxZJm4edhj0bkd" +
	"EtkxLCNUGDQKsywnKOTWzfefT9UCQJyLwt74ThJtNX7uoYrfAHNfBARk3Kx+wf4U" +
	"Grd2GmSe8Lnr3FNcZ/uMJffsYvBk3fbDwYsVC6rd4BuJvvri3K1dti3rnvDEnuMI" +
	"Ve7a2n7NE7yV0cietIjKeeY8bO25lwrTtBzgP5y1G9spjzAtiRLZAgMBAAEwDQYJ" +
	"KoZIhvcNAQEFBQADggEBAMkYPFmsHYlyO+KZMKEWUWOdw1rwrIVhLQOKqLz8Wbe8" +
	"lIQ5pdsd4S1DqvMEzYyMtpZckZ9mOBZh/SQsmdb8sZnQwiMvlPSO6IWp/MpuP+VK" +
	"v8IBAr1aaLlMaelV086uIFc9coE6XAdWFrGlUT9FYM00JwoSfi51vbcqbIh6P8y9" +
	"uwHqlt2vkVYujto+p0UMBnBZkfKBgzMG7ILWpJbVszmpesVzI2XUgq8BxlO0fvw5" +
	"m/R4bAtHqXTK0xVrTBXUg6izFbdA3pVlFMiuv8Kq2cyBg+VkXGYmZ37BGhApe5Le" +
	"Dabe4iGcXQMW4lunjRSv8gDu/ODA/20OMNVDOx92MTIxggIqMIICJgIBATAYMBMx" +
	"ETAPBgNVBAMMCGNtcy10ZXN0AgEAMA0GCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3" +
	"DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTEyMDIwNTM0M1ow" +
	"LwYJKoZIhvcNAQkEMSIEIGjmVrJR5n6DWL74SDqw1RxmGfPnoanw51g41B/zaPco" +
	"MHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglg" +
	"hkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMC" +
	"AgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJHB" +
	"kfH1hZ4Y0TI6PdW7DNFnb++KQJiu4NmzE7SyTJOCxC2W44uAKUdJw7c8cdn/lcb/" +
	"y1kvwNbi2kysuZSTpywBIjHSTw3BTwdaNJFd6HUV1mX2IQRfaJIPW5fqkhLfQtZ6" +
	"LZka/HWQ5fwA51g6lVNTMbStjsPlBef6qEDcCLMp/4CNEqC5+fUx8Jb7Q5mvyCHQ" +
	"3IZrIEMLBYhrgrm61qh/MXKnAqlEo6XxN1fL0CXDxy9dYPSKr2G66o9+BjmYktF5" +
	"3MfxrT4JDizd2S/8BVEv+H+uHmrpyRxMceREPJVrVHOdd922hyKALbAGcoyMdXpj" +
	"ZdMtHnR5z07z9wxvwiw=",
)

var fixtureSignatureOpenSSLDetached = mustBase64Decode("" +
	"MIIFCQYJKoZIhvcNAQcCoIIE+jCCBPYCAQExDzANBglghkgBZQMEAgEFADALBgkq" +
	"hkiG9w0BBwGgggKjMIICnzCCAYegAwIBAgIBADANBgkqhkiG9w0BAQUFADATMREw" +
	"DwYDVQQDDAhjbXMtdGVzdDAeFw0xNzExMjAyMTE0NDdaFw0yNzExMTgyMTE0NDda" +
	"MBMxETAPBgNVBAMMCGNtcy10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
	"CgKCAQEA5VQ0FRvQRA9F+6nss77yUcm3x8IOoJV/icQrtrkR/BHGgeepcLIcHkWh" +
	"s/cap69xR5TCtONy0I4tqKf/vXnKXvMjsGGrecFMi8NVTbEoNg9m47nbdO7BY1+f" +
	"waLfwAX5vf17BRSqA0wRIoNIzJc07mNrI84EbKfVmDtPrqzwnT0sIKqj5p2PQdWi" +
	"sPwOocLYJBdAPglnLuFk6WTZalJRgV7h50nl1GBDKJVo1Yc7zqPdqWzHzFqK759g" +
	"CHBZMYJdqIx/wev/l66oEcJZr6gnnKzq8lsWljpjVWD96z/W/fehWZsWlWkvmrus" +
	"qizMbL0vCx8HrReo7+hszMIHR5bwTwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAD" +
	"ZjPxm/JHc4KoQUaVOSAU97lO60MD21Ud0LtaebbiSJnaMH9a/rb3kuxJAKVSBhDp" +
	"wyRK19KNtaSXHEAD48aJeT7J4wsDJFNfKGx/9R2iYB5xjc/POpK13A/o4fDrpLWL" +
	"1doIc0KjVA63BXaYOwsEj2iKzUKNFZ2kS3bXMkEBhUDUXtSo08WFI7UkgYTuIfM2" +
	"LS/wyORcwZIEIvq+ndkch/nAyQZ8U0/85dgwpOQcyZ0UDiu8Ti9z9IUlhxSq2T13" +
	"JhIfiMa4m27y71JmsFy12uN3fGBckkyNkKkxVMy0H4Ukr1hq/ZkvH3HdrEnWmNEu" +
	"WdU7WvIBsbe3U2idyhBSMYICKjCCAiYCAQEwGDATMREwDwYDVQQDDAhjbXMtdGVz" +
	"dAIBADANBglghkgBZQMEAgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB" +
	"MBwGCSqGSIb3DQEJBTEPFw0xNzExMjAyMTE0NDdaMC8GCSqGSIb3DQEJBDEiBCBo" +
	"5layUeZ+g1i++Eg6sNUcZhnz56Gp8OdYONQf82j3KDB5BgkqhkiG9w0BCQ8xbDBq" +
	"MAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3" +
	"DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggq" +
	"hkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQAcLsBbjvlhz+HAy7m5cvh8tRav" +
	"xT05fFK1hwBC287z+D/UaCrvrd2vR4bdUV8jfS5iTyUfX/BikOljxRwUMgtBLPKq" +
	"gdNokoxUoQiqVOdgCER0isNLF/8+O29reI6N/9Mp+IpfE41o2xcRrggfncuPX00K" +
	"MB2K4/ZF35HddfblHIgQ+9gWfHE52KMur4XeI5sc/izMNuPyR8VVB7St5JLMepHj" +
	"UtbPYBJ0bRSwDX1JAoB+Ze/mPvCmo/pS5QyYfNvXg3Jw4TVoud5+oUH9r6MwSxzN" +
	"BSws5SM9d0GAafR+Hj19x9s8ypUjLJmGIAjeTrlgcYUTJjnfEtZBL5Je2FuK",
)

var fixtureSignatureOutlookDetached = mustBase64Decode("" +
	"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" +
	"MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDBDBgNVHSAEPDA6MDgGCmCGSAGG/WwEAQIw" +
	"KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBiAYDVR0fBIGAMH4w" +
	"PaA7oDmGN2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDQS1n" +
	"Mi5jcmwwPaA7oDmGN2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVk" +
	"SURDQS1nMi5jcmwweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp" +
	"Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy" +
	"dFNIQTJBc3N1cmVkSURDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBADh2DYGfn+1eg21dTa34iZlu" +
	"IyActG/S23bCLnJSThPbiCfZgGkKr9Bq6TSJ4qQfsquIB7cO46mJ+tzHL570xAsJ4pC7z3RhBdzK" +
	"j9uT6ZUExdHQs2FoPjU5uT1UhqHv7T9qYp689XpZ2xPLH59SwLASIVnoQFIS0MKT8AN6ZgKxDWDY" +
	"EUyRfGQxxDbfqWhncH0qxT20mv8TnvIMo2ngsCBZfpJcv9u3LijnD7uVCZ2qRIJkmJ7s1eoGc05c" +
	"Z+7NeA8vC28BgGe2svMUlRInaNsMDUBmizI4x6DnS8uVlX22KAdPML9NvPOfCGCohDevZgCSMx/o" +
	"nH+foA+rOCngkR8wggZOMIIFNqADAgECAhAErnlgZmaQGrnFf6ZsW9zNMA0GCSqGSIb3DQEBCwUA" +
	"MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp" +
	"Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzExMDUx" +
	"MjAwMDBaFw0yODExMDUxMjAwMDBaMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ" +
	"bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIgQXNz" +
	"dXJlZCBJRCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANz4ESM/arXvwCd5Gy0F" +
	"h6IQQzHfDtQVG093pCLOPoxw8L4Hjt0nKrwBHbYsCsrdaVgfQe1qBR/aY3hZHiIsK/i6fsk1O1bx" +
	"H3xCfiWwIxnGRTjXPUT5IHxgrhywWhgEvo8796nwlJqmDGNJtkEXU0AyvU/mUHpQHyVF6PGJr83/" +
	"Xv9Q8/AXEf+9xYn1vWK52PuORQSFbZnNxUhN/SarAjZF6jbXX2riGoJBCtzp2fWRF47GIa04PBPm" +
	"Hn9mnNVN2Uba9s9Sp307JMO0wVE1xpvr1O9+5HsD4US9egs34E/LgooNcRjkpuCJLBvzsnM8wbCS" +
	"nhh9vat9xX0IoSzCn3MCAwEAAaOCAvgwggL0MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/" +
	"BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu" +
	"Y29tMIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRB" +
	"c3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl" +
	"cnRBc3N1cmVkSURSb290Q0EuY3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDCCAbMG" +
	"A1UdIASCAaowggGmMIIBogYKYIZIAYb9bAACBDCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3" +
	"LmRpZ2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABv" +
	"AGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQA" +
	"ZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0" +
	"ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQA" +
	"eQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBp" +
	"AGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUA" +
	"cgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0OBBYEFOcCI4AAT9jXvJQL" +
	"2T90OUkyPIp5MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUA" +
	"A4IBAQBO1Iknuf0dh3d+DygFkPEKL8k7Pr2TnJDGr/qRUYcyVGvoysFxUVyZjrX64GIZmaYHmnwT" +
	"J9vlAqKEEtkV9gpEV8Q0j21zHzrWoAE93uOC5EVrsusl/YBeHTmQvltC9s6RYOP5oFYMSBDOM2h7" +
	"zZOr8GrLT1gPuXtdGwSBnqci4ldJJ+6Skwi+aQhTAjouXcgZ9FCATgLZsF2RtJOH+ZaWgVVAjmbt" +
	"gti7KF/tTGHtBlgoGVMRRLxHICmyBGzYiVSZO3XbZ3gsHpJ4xlU9WBIRMm69QwxNNNt7xkLb7L6r" +
	"m2FMBpLjjt8hKlBXBMBgojXVJJ5mNwlJz9X4ZbPg4m7CMYIDvzCCA7sCAQEweTBlMQswCQYDVQQG" +
	"EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQw" +
	"IgYDVQQDExtEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ0ECEAWkzvCWLw1xJSpSGJSTKHAwDQYJ" +
	"YIZIAWUDBAIBBQCgggIXMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8X" +
	"DTE3MTEyOTE0NDMxOVowLwYJKoZIhvcNAQkEMSIEIEgBjCiMhZLBevfHienSec11YNE+P7PSd4JD" +
	"wfCQCrwWMIGIBgkrBgEEAYI3EAQxezB5MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy" +
	"dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIg" +
	"QXNzdXJlZCBJRCBDQQIQBaTO8JYvDXElKlIYlJMocDCBigYLKoZIhvcNAQkQAgsxe6B5MGUxCzAJ" +
	"BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j" +
	"b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDQQIQBaTO8JYvDXElKlIYlJMo" +
	"cDCBkwYJKoZIhvcNAQkPMYGFMIGCMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCgYIKoZIhvcN" +
	"AwcwCwYJYIZIAWUDBAECMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDALBglghkgBZQME" +
	"AgEwCwYJYIZIAWUDBAIDMAsGCWCGSAFlAwQCAjAHBgUrDgMCGjANBgkqhkiG9w0BAQEFAASCAQBh" +
	"AjkUd98Si7LKxELWdwY8yrqrfK61JxVSxSY/BkF3xS/0QbQMU9Y+0V23nJX5ymamgCd9yNTdNapV" +
	"D4OzoVXfmTqd1/AD30M1a1CdBVoNGV8X4Uv8Z1fAl5MN+6Yt1CeIun39gvkutAgUmvCVrjFN+gD6" +
	"GH+VTQNGHr3wxdmtL9F8WeNECvpVgYEMqnYRrYHw4B6euJRsy4UnB4Sy/ogV1elkipxCbqRovPU1" +
	"pVeKhkfYuRlsLwbBwQPKvzcfUU3ZJua4I3AKKPxlqdY8uP72A5iObDTL8kHhSRMtVVHoruVzgJPZ" +
	"+9Mfsz41eM4pJSPDKZPYD9rH6cUKJI8xEnmCAAAAAAAA",
)

var fixturePFX = mustBase64Decode("" +
	"MIIDIgIBAzCCAugGCSqGSIb3DQEHAaCCAtkEggLVMIIC0TCCAccGCSqGSIb3" +
	"DQEHBqCCAbgwggG0AgEAMIIBrQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYw" +
	"DgQIhJhqIE0wYvgCAggAgIIBgFfQz7+5T0RBGtlNHUjM+WmjJFPPhljOcl5v" +
	"SEFWi2mNpSuUIcaNQlhUTxBX7hUJRq6eW3J5T20hY3WBomC6cy4sRpAZlOSD" +
	"o/UYrQG6YIFc+X97t8E1M8bihsmp9GEBEdLCDCwhrIpFX7xuxfudYH9MLRKA" +
	"dKwJ8xqrpFjgFFbosvKHoqi0gH2RLS7+G8V5wReWTOVKvzy3zD8XlMgtdSUn" +
	"G+MiP0aaa8jFGfprFoeMMJJr5cO89UjjC+qYkcqA9HP7mf2VmenEJSJt7E06" +
	"51CE3/eaEONgoIDudTXZt8CB4vvbOnL8QfmVp2kzKKl1hsN43jPVvRqbM6+4" +
	"OR1Yp3T1UVKLcGwpZCh3t/fYgpyjBqrQqEWQzhKs+bTWlCeDpXdxhHJIquHh" +
	"zZ8Sm2s/r1GDv7kVLw9d8APyWep5WrFVE/r7kN9Ac8tbiqTM54sFMTQLkzhP" +
	"TIhNdjIQkn8i0H2673cGYkFYWLIO+I8jFhMl3ZBwQt54Wnb35zInpchoQjCC" +
	"AQIGCSqGSIb3DQEHAaCB9ASB8TCB7jCB6wYLKoZIhvcNAQwKAQKggbQwgbEw" +
	"HAYKKoZIhvcNAQwBAzAOBAhlMkjWb0xXBAICCAAEgZALV1NzLJa6MAAaYkIs" +
	"eJRapR+h9Emzew5dstSbB23kMt3PLyafv4M0AvUi3Mk+VEowmL62WhC+PcQf" +
	"dE4YaW6PvepWjS+gk42RA6hT8zdG2PiP2rhS4wuxs/I/rPQIgY8i3M2RGmrR" +
	"9CcOFCE7hnpJp/0tm7Trc11SfCNB3MXYSvttL5ZJ29ewYZ9kg+lv0XoxJTAj" +
	"BgkqhkiG9w0BCRUxFgQU7q/jH1Mc5Ctiwkdl0Hx9xKSYy90wMTAhMAkGBSsO" +
	"AwIaBQAEFDPX7JM9l8ZnTwGGaDQQvlp7RiBKBAg2WsoFwawSzwICCAA=",
)

var fixtureTimestampSymantec = mustDecodeTimestampResponse("" +
	"MIIDnjADAgEAMIIDlQYJKoZIhvcNAQcCoIIDhjCCA4ICAQMxDTALBglghkgBZQMEAgEwggEOBgsqhkiG" +
	"9w0BCRABBKCB/gSB+zCB+AIBAQYLYIZIAYb4RQEHFwMwMTANBglghkgBZQMEAgEFAAQgWJG1tSLV3wht" +
	"D/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgMCFHERZNISITpb8tPCqDQtcNGcWhhSGA8yMDE4MDUwOTE0NTQy" +
	"MlowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u" +
	"MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYg" +
	"VGltZVN0YW1waW5nIFNpZ25lciAtIEcyMYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAbBgNV" +
	"BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgw" +
	"JgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhBUWPKq10HWRLyEqXugllLmMAsG" +
	"CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4" +
	"MDUwOTE0NTQyMlowLwYJKoZIhvcNAQkEMSIEIF/3JTU7CB+pzL3Mf+8BKgIRZQlDbovL5WzNhyeTSCn6" +
	"MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIM96wXrQR+zV/cNoIgMbEtTvB4tvK0xea6Qfj/LPS61nMAsG" +
	"CSqGSIb3DQEBAQSCAQCRxSB9MLAzK4YnNoFqIK9i71b011Q4pcyF6FEffC3ihOHjdmaHf/rFCeuv4roh" +
	"yGxW9cRTshE8UohcghMEuSbkSyaFtVt37o31NC1IvW0vouJVQ0j0rg6nQjlsO9rMGW7cJOS2lVnREqk5" +
	"+WfBMKJVnuYSXrnUdxcjSG++4eBCEF5L1fdCVjm4s1hagEORimvUoKuStibW0lwE8rdOEBjusZjRPDV6" +
	"hudDhI+2SJPCAFhnNaDDT73y+Ux4x5cVdxHV+tME8kUrr6Hm/l6EyPxu/jwrV/EdJFVsJfkemdJz/ACa" +
	"EbbTXfP8KuOwEyUwbFbRCXqO+Z6Gg0RqpiAZWCSM",
)

var fixtureTimestampSymantecWithCerts = mustDecodeTimestampResponse("" +
	"MIIOLTADAgEAMIIOJAYJKoZIhvcNAQcCoIIOFTCCDhECAQMxDTALBglghkgBZQMEAgEwggEOBgsqhkiG" +
	"9w0BCRABBKCB/gSB+zCB+AIBAQYLYIZIAYb4RQEHFwMwMTANBglghkgBZQMEAgEFAAQgWJG1tSLV3wht" +
	"D/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgMCFDSZty7Ob7ZraC01Jcblagd3PcnYGA8yMDE4MDUwOTE4MjUy" +
	"MlowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u" +
	"MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYg" +
	"VGltZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE98mJ0pwZnRIw" +
	"DQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0G" +
	"A1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIElu" +
	"Yy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJv" +
	"b3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTExMjM1OTU5WjB3" +
	"MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFu" +
	"dGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0Ew" +
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aa" +
	"JwAyl2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8utG7/YlZHz8O5s" +
	"+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9IThxNF8ccYGKbQ/5IMNJsN7CD5N+Qq3" +
	"M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1" +
	"inisGTKPI8EyQRtZDqk+scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIB" +
	"czAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUB" +
	"BxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0" +
	"dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Mu" +
	"c3ltY2QuY29tMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9v" +
	"dC5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFt" +
	"cC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHViMB8GA1UdIwQYMBaAFLZ3+mlIR59T" +
	"EtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUAA4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociB" +
	"iPenjxXmQCmt5l30otlWZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rST" +
	"yEyQY0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72a433Snq+8839" +
	"A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnjOgC/zoqUywHbnsc4uw9Sq9HjlANg" +
	"Ck2g/idtFDL8P5dA4b+ZidvkORS92uTTw+orWrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIB" +
	"AgIQe9Tlr7rMBz+hASMEIkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMU" +
	"U3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNV" +
	"BAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMTcxMjIzMDAwMDAwWhcNMjkwMzIy" +
	"MjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYD" +
	"VQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0" +
	"YW1waW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArw6Kqvjcv2l7" +
	"VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/J0ozTm0WiuSNQI0iqr6nCxvSB7Y8" +
	"tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uPCB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmq" +
	"ChhsVWFX0fECLMS1q/JsI9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7Dby" +
	"lpWBJiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTOPAPstwDyOiLF" +
	"tG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcD" +
	"MEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBz" +
	"Oi8vZC5zeW1jYi5jb20vcnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50" +
	"ZWMuY29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE" +
	"AwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVj" +
	"LmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1j" +
	"YS5jZXIwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUT" +
	"AamfhcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHViMA0GCSqGSIb3" +
	"DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5Rk7nfmUGWIu8V4qSDQjYELo2JPoK" +
	"e/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmiWRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3" +
	"P4bm9sB/RDxGXBda46Q71Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0" +
	"zd9HCYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEsHwA/w0sUxmcc" +
	"zB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAb" +
	"BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3Jr" +
	"MSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0S" +
	"MAsGCWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8X" +
	"DTE4MDUwOTE4MjUyMlowLwYJKoZIhvcNAQkEMSIEIF5EOTCml8PvDOxSGeQnbCv+jXprtZlEut7wcOx/" +
	"xjfvMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4" +
	"MAsGCSqGSIb3DQEBAQSCAQBD1SGuMSSNtmwg38x/1d8v+uvX/2aPIJQS//p5Q54Y8moIEeezRhG0tK3N" +
	"81tfKdLeYTVE6VL8D7ZaCpbKzNJeD6DQM4S87bzH88H5RQOb2JTCvBPF3C/ytcl7ylezx6xsFNtftbW3" +
	"IOXETaWLgIBpeL7jUZQDhgQ4Xb9HeFl4vA6Wk2kR88h+8Tv2ci0AI9hZgHhH9c/OwPvd8TKbhSjK9qXK" +
	"DjaJr0BeVuYHPSWxfsxWVCOjNIOg7moWpPLSYQpqM2gdg5ppjQWffWYC4rywmM6XsBKs+EKFb++4GSOc" +
	"wc6JJCugxm8Ba1a6nDAAAQYf/pQyBRRlh/qCHZ0rIoFq",
)

var fixtureTimestampDigicert = mustDecodeTimestampResponse("" +
	"MIIOuTADAgEAMIIOsAYJKoZIhvcNAQcCoIIOoTCCDp0CAQMxDzANBglghkgBZQMEAgEFADB3BgsqhkiG" +
	"9w0BCRABBKBoBGYwZAIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8IbQ/wsRD7" +
	"2dIbtPxxY6800IKGouhG9r4DAhAvZIfDsFuq0GRqVn9Wu2I8GA8yMDE4MDUwOTE4NDgxOFqgggu7MIIG" +
	"gjCCBWqgAwIBAgIQCcD8RsgEQhO1WYuvKE9OQTANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEV" +
	"MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhE" +
	"aWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTE3MDEwNDAwMDAwMFoXDTI4" +
	"MDExODAwMDAwMFowTDELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSowKAYDVQQDEyFEaWdp" +
	"Q2VydCBTSEEyIFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" +
	"AQCelZhqNDtzG6h+/Me+KWmJx2gmRl89jWJzh4GjoZzwt1skN1qS1PRZ13aJ5NzVJ/DVZrwK7rQrMWes" +
	"WMVKkVkrRR4JAdZks1nujWZN+yNezBANC4pn71KuoAiQwlL39ai1bpsse53ntT77eM0yUBi/QLVMjLtX" +
	"9KBPEUVsQkK55a/W3/SnfApolg/SXylXzvsdMv/0EaETIvsSy+/XU9Lrl8uirBsdnVghUYLCwt7qKz8s" +
	"IoTQQ+w7Oz9HxPZW3EU3mLRrdLVZr3hXacgPCQJ43dhTwZnbYMSd6q6v4H6GSlypWGGoXnSKAShock6n" +
	"hp21AlKHcGZI047vgSTM3NhlAgMBAAGjggM4MIIDNDAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw" +
	"ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIB" +
	"kjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIB" +
	"Vh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUA" +
	"IABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUA" +
	"IABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkA" +
	"bgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQA" +
	"IABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUA" +
	"ZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYD" +
	"VR0jBBgwFoAU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHQYDVR0OBBYEFOGnMkruASEofVTV8geSbrQHDz2H" +
	"MHEGA1UdHwRqMGgwMqAwoC6GLGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMu" +
	"Y3JsMDKgMKAuhixodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDCBhQYI" +
	"KwYBBQUHAQEEeTB3MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTwYIKwYBBQUH" +
	"MAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURUaW1lc3Rh" +
	"bXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBAB7wQYIyru3xtDUT3FDC1ZeuIiKdDg6vM9NM/Xy/" +
	"bwERp5RlIlzGIqHIiVJrmoxzXNlePzLeFmBMizb9MZkKvcGEt40d74kmEwVW80fNR1uthLI4r2ojtUXj" +
	"HogyRoDSt6aZIv3BeM/1i9gMjAUJ7kTmgNVtcMyfUx4n3SpI3tqTZa1uZaOZp8JADnPMWE+PRSjlvJyI" +
	"5ijOYF0tJV2Lcy6lDVtR2ppO/1AFiSja8ni70lh4jUSnrDoAkXhpiWQE012W3yq/+aVMLJP/5ordgqzx" +
	"0rOihprBVYlWakc/+tYzlUM1iQV4Wjpp2iK4BEPTb2g1NnoUPkXpmGSGDxMMJkowggUxMIIEGaADAgEC" +
	"AhAKoSXW1jIbfkHkBdo2l8IVMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE" +
	"aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFz" +
	"c3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0zMTAxMDcxMjAwMDBaMHIxCzAJBgNVBAYT" +
	"AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV" +
	"BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB" +
	"AQUAA4IBDwAwggEKAoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5fU1ofue2oPSNs4jk" +
	"l79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb6+NGRwYaVX4LJ37AovWg4N4iPw7/fpX7" +
	"86O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU46gJcWvgzyIQD3XPcXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8" +
	"YGqsLwfM/fDqR9mIUF79Zm5WYScpiYRR5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfx" +
	"FwbvPc3WTe8GQv2iUypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAdBgNVHQ4EFgQU9Lbh" +
	"IB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wEgYDVR0TAQH/" +
	"BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgweQYIKwYBBQUHAQEE" +
	"bTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6" +
	"Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6" +
	"MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j" +
	"cmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j" +
	"cmwwUAYDVR0gBEkwRzA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj" +
	"ZXJ0LmNvbS9DUFMwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLpUYdWac3v3dp8qmN6" +
	"s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQdaq6Z+CeiZr8JqmDfdqQ6kw/4stHYfBli" +
	"6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC4HLHmNY8ZOUfSBAYX4k4YU1iRiSHY4yRUiyvKYnleB/WCxSl" +
	"gNcSR3CzddWThZN+tpJn+1Nhiaj1a5bA9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6H" +
	"USHkWGCbugwtK22ixH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIvIjayS6JKldj1po5S" +
	"MYICTTCCAkkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE" +
	"CxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVz" +
	"dGFtcGluZyBDQQIQCcD8RsgEQhO1WYuvKE9OQTANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0BCQMx" +
	"DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDgxOFowLwYJKoZIhvcNAQkEMSIE" +
	"IDpdtczqob9pSfKx5ZEHQZSSHM3P+8uGHy1rXmrK9iUjMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFEAB" +
	"kUdcmIkd66EEr0cJG1621MvLMA0GCSqGSIb3DQEBAQUABIIBAIlFY+12XT6zvj4/0LVL5//VunTmYTKg" +
	"Z6eSrafFT9zOvGbDzm/8XnDLrUQq9Y4kQpE+eKfHWJOBQQZ0ze0wftUml+iRsvqEVlax7G03SzHyPIYH" +
	"HzEH/IKRlryHR5LgzzeFqS6IdVg18FBLvrs2fvPJlsj0ZGmAbwn6ntHDromtnkwZV6Cir5gH+wSKuA+Z" +
	"3Qj5odgrTQ9gmbmNlFgwp4BwH/vFbBB1eIt7EUD1KfZzThfdFYHnyl8eRcE5p5+MxvyAC78fPzlSlJJP" +
	"OES5LDDTx/Qvhet0PjJv70Z7kKgMmAA0BMTRuTnGfiVfEoFm2bzoKmwprU38EPz+PVnrbUA=",
)

var fixtureTimestampComodo = mustDecodeTimestampResponse("" +
	"MIIDuDADAgEAMIIDrwYJKoZIhvcNAQcCoIIDoDCCA5wCAQMxDzANBglghkgBZQMEAgEFADCCAQ8GCyqG" +
	"SIb3DQEJEAEEoIH/BIH8MIH5AgEBBgorBgEEAbIxAgEBMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8I" +
	"bQ/wsRD72dIbtPxxY6800IKGouhG9r4DAhUA4Fc3zQPRFgrg3c8/sksclhBco7QYDzIwMTgwNTA5MTg0" +
	"NzQyWqCBjKSBiTCBhjELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G" +
	"A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxLDAqBgNVBAMTI0NPTU9ETyBT" +
	"SEEtMjU2IFRpbWUgU3RhbXBpbmcgU2lnbmVyMYICcTCCAm0CAQEwgaowgZUxCzAJBgNVBAYTAlVTMQsw" +
	"CQYDVQQIEwJVVDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg" +
	"TmV0d29yazEhMB8GA1UECxMYaHR0cDovL3d3dy51c2VydHJ1c3QuY29tMR0wGwYDVQQDExRVVE4tVVNF" +
	"UkZpcnN0LU9iamVjdAIQTrCHj8wkNTay2Mn3vzlVdzANBglghkgBZQMEAgEFAKCBmDAaBgkqhkiG9w0B" +
	"CQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDc0MlowKwYLKoZIhvcNAQkQ" +
	"AgwxHDAaMBgwFgQUNlJ9T6JqaPnrRZbx2Zq7LA6nbfowLwYJKoZIhvcNAQkEMSIEIJeVWgArDRySkAZc" +
	"F6na8PZrsUBoQs2jUzy94iOFYfM6MA0GCSqGSIb3DQEBAQUABIIBAKKV56NeTuFn4VdoNv15X0bUWG3p" +
	"JSMRVbp1CWktnraj7E5m3BUmFlb4Dwrf3IMmE4QJrGrzDUWtUmpnHR4VuGAUmyajEcmDICc2gpBBG+aV" +
	"0Ng/lXQ1xAotKkU7/4wNQY1nOBsquZykYRHWbzJaVxaq8VEc0nVZY2o1TVDgWtLF7BHAd96vw4iVuG3O" +
	"Pb8izdFMwQ0t/TMNq0FD0hEFQDSTvVkayeaficblGbhf/p1xuCxSMoFBmnfO56aRX01E3SDNAgo3/hFl" +
	"na2g8ESpdWHRMqG3+8ehvgMwljUnhj5+iYT1YF7Rm6KcV2TCIh6QyokN42ji4BMqTlBA7vzSx5A=",
)

var fixtureTimestampGlobalSign = mustDecodeTimestampResponse("" +
	"MIIDoTADAgEAMIIDmAYJKoZIhvcNAQcCoIIDiTCCA4UCAQMxCzAJBgUrDgMCGgUAMIHdBgsqhkiG9w0B" +
	"CRABBKCBzQSByjCBxwIBAQYJKwYBBAGgMgICMDEwDQYJYIZIAWUDBAIBBQAEIFiRtbUi1d8IbQ/wsRD7" +
	"2dIbtPxxY6800IKGouhG9r4DAhRYZmxGjSg8ojY0mWZG3dUdVW0mAxgPMjAxODA1MDkxODQ2MjRaoF2k" +
	"WzBZMQswCQYDVQQGEwJTRzEfMB0GA1UEChMWR01PIEdsb2JhbFNpZ24gUHRlIEx0ZDEpMCcGA1UEAxMg" +
	"R2xvYmFsU2lnbiBUU0EgZm9yIFN0YW5kYXJkIC0gRzIxggKRMIICjQIBATBoMFIxCzAJBgNVBAYTAkJF" +
	"MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFtcGlu" +
	"ZyBDQSAtIEcyAhIRIbRVNR67GrJPl+8H/iqzC4owCQYFKw4DAhoFAKCB/zAaBgkqhkiG9w0BCQMxDQYL" +
	"KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE4MDUwOTE4NDYyNFowIwYJKoZIhvcNAQkEMRYEFOmL" +
	"BqSyLEaL7tN+hDwnk6fha6wfMIGdBgsqhkiG9w0BCRACDDGBjTCBijCBhzCBhAQUg/3hunb+9VKRtQ1o" +
	"YZBtqkW1jLUwbDBWpFQwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAm" +
	"BgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEhtFU1Hrsask+X7wf+KrMLijAN" +
	"BgkqhkiG9w0BAQEFAASCAQBhWhjTagaTyATim1IHw0tF0wb22rlj6qXki86lclB/2uxBC8/3uLVd259z" +
	"iz7aaTmxSj3ksMBq9A75beQW5Be9vK00B/mj/p1dLrtgCcYZtV4uhoBkBx0YbriumEnvQoQL1bI1EiXh" +
	"TDbdTrGs2wXn3Xzw/qwqc7w+IjW1BjqzLf6BB9jw2raxMuWBA3EGMwGTumRx5x6a7j2Jx/9Uhs+3ce+9" +
	"ZRDtiWAFCkTQVvNLrAuHLTFK6lLOqfucrru76adpJMlTJ+VRut0adpwviS1Cb2ifIX1iUHjtGssihk6v" +
	"/tt7Yo4J341G5pC4JDXXhJvxHImNew3l0BWM0LROEgLM",
)

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// our timestamp fixtures are complete RFC3161 response SEQUENCEs. The first
// element is a status and the second is the timestamp token that we really care
// about.
func mustDecodeTimestampResponse(b64 string) []byte {
	ber := mustBase64Decode(b64)

	der, err := ber2der(ber)
	if err != nil {
		panic(err)
	}

	resp := struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}{}

	if rest, err := asn1.Unmarshal(der, &resp); err != nil {
		panic(err)
	} else if len(rest) > 0 {
		panic(errors.New("unexpected trailing data"))
	}

	return resp.Token.FullBytes
}
