package cms

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"golang.org/x/crypto/pkcs12"
)

func TestSign(t *testing.T) {
	priv, cert, err := pkcs12.Decode(fixturePFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{cert}

	data := []byte("hello, world!")

	ci, err := Sign(data, chain, priv.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if err = sd2.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSignDetached(t *testing.T) {
	priv, cert, err := pkcs12.Decode(fixturePFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{cert}

	data := []byte("hello, world!")

	ci, err := SignDetached(data, chain, priv.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if err = sd2.VerifyDetached(data); err != nil {
		t.Fatal(err)
	}
}

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
