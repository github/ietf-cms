package protocol

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"
)

func TestParseFixtureSignatureOne(t *testing.T) {
	ParseContentInfoHelper(t, fixtureSignatureOne)
}

func TestParseSignatureGPGSM(t *testing.T) {
	ParseContentInfoHelper(t, fixtureSignatureGPGSM)
}

func TestParseSignatureNoCertsGPGSM(t *testing.T) {
	ParseContentInfoHelper(t, fixtureSignatureNoCertsGPGSM)
}

func ParseContentInfoHelper(t *testing.T, ber []byte) {
	t.Helper()

	ci, err := ParseContentInfo(ber)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd.X509Certificates(); err != nil {
		t.Fatal(err)
	}

	if !sd.EncapContentInfo.EContentType.Equal(oidData) {
		t.Fatalf("expected %s content, got %s", oidData.String(), sd.EncapContentInfo.EContentType.String())
	}

	if _, err = sd.EncapContentInfo.DataEContent(); err != nil {
		t.Fatal(err)
	}

	for _, si := range sd.SignerInfos {
		// Allow either CHOICE for SID.
		if _, err = si.IssuerAndSerialNumberSID(); err != nil {
			if _, err = si.SubjectKeyIdentifierSID(); err != nil {
				t.Fatal(err)
			}
		}

		if _, err = si.SubjectKeyIdentifierSID(); err != nil {
			if _, err = si.IssuerAndSerialNumberSID(); err != nil {
				t.Fatal(err)
			}
		}

		ct, err := si.GetContentTypeAttribute()
		if err != nil {
			t.Fatal(err)
		}
		// signerInfo contentType attribute must match signedData
		// encapsulatedContentInfo content type.
		if !ct.Equal(sd.EncapContentInfo.EContentType) {
			t.Fatalf("expected %s content, got %s", sd.EncapContentInfo.EContentType.String(), ct.String())
		}

		md, err := si.GetMessageDigestAttribute() // TODO: test digest size equals hash size
		if err != nil {
			t.Fatal(err)
		} else if len(md) == 0 {
			t.Fatal("nil/empty message digest attribute")
		}

		var nilTime time.Time
		st, err := si.GetSigningTimeAttribute()
		if err != nil {
			t.Fatal(err)
		}
		if st == nilTime {
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

	der2, err = asn1.Marshal(sd)
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

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
