package cms

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOne)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.Verify(UnsafeNoVerify); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyGPGSMAttached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureGPGSMAttached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd.Verify(UnsafeNoVerify); err != nil {
		t.Fatal(err)
	}

	data, err := sd.GetData()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hello\n")) {
		t.Fatal("bad msg")
	}
}

func TestVerifyGPGSMDetached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureGPGSM)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!\n"), UnsafeNoVerify); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyGPGSMNoCerts(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureNoCertsGPGSM)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!\n"), UnsafeNoVerify); err.Error() != "no certificates" {
		t.Fatal(err)
	}
}

func TestVerifyOpenSSLAttached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOpenSSLAttached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.Verify(UnsafeNoVerify); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOpenSSLDetached(t *testing.T) {
	sd, err := ParseSignedData(fixtureSignatureOpenSSLDetached)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.VerifyDetached([]byte("hello, world!"), UnsafeNoVerify); err != nil {
		t.Fatal(err)
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

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
