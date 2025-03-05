package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func BytesToPrivKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	return x509.ParsePKCS1PrivateKey(block.Bytes) // return (prv, nil) or (nil, err)
}

func BytesToPubKey(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	return x509.ParsePKCS1PublicKey(block.Bytes) // return (prv, nil) or (nil, err)
}
