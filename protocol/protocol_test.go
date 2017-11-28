package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"io"
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

	sd, err := NewSignedData(msg)
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

	newECI, err := NewDataEncapsulatedContentInfo(oldData)
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

func TestParseFixtureSignatureOne(t *testing.T) {
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

	if !sd.EncapContentInfo.EContentType.Equal(oidData) {
		t.Fatalf("expected %s content, got %s", oidData.String(), sd.EncapContentInfo.EContentType.String())
	}

	if _, err = sd.EncapContentInfo.DataEContent(); err != nil {
		t.Fatal(err)
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

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
