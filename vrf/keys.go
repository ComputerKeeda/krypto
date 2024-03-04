package vrf

import (
	"encoding/hex"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func NewKeyPair() (privateKeyX kyber.Scalar, publicKeyX kyber.Point) {
	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate a new private key
	privateKey := suite.Scalar().Pick(suite.RandomStream())

	// Derive the public key from the private key
	publicKey := suite.Point().Mul(privateKey, nil)

	return privateKey, publicKey
}

func GeneratePublicKey(privateKey kyber.Scalar) kyber.Point {
	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()
	// Derive the public key from the private key
	publicKey := suite.Point().Mul(privateKey, nil)
	return publicKey
}

func LoadHexPrivateKey(hexPrivateKey string) (privateKey kyber.Scalar, err error) {
	// Initialize the Kyber suite for Edwards25519 curve
	// Convert the hexadecimal string to a byte slice
	privateKeyBytes, err := hex.DecodeString(hexPrivateKey)
	if err != nil {
		fmt.Printf("Error decoding private key: %v\n", err)
		return nil, err
	}

	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Convert the byte slice into a Kyber scalar
	privateKey = suite.Scalar().SetBytes(privateKeyBytes)
	return privateKey, nil
}
