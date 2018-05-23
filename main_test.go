package cms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/mastahyeti/fakeca"
)

var (
	root = fakeca.New(fakeca.IsCA)

	intermediateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediate       = root.Issue(fakeca.IsCA, fakeca.PrivateKey(intermediateKey))

	leaf      = intermediate.Issue()
	otherRoot = fakeca.New(fakeca.IsCA)
)
