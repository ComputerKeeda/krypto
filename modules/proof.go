package modules

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

// Function to generate a unique proof using the private key and serialized data
func GenerateUniqueProof(privateKey kyber.Scalar, data []byte) ([]byte, error) {
	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Sign the data using Schnorr signature scheme and private key
	signature, err := schnorr.Sign(suite, privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// Function to verify a unique proof using the public key, original data, and proof
func VerifyUniqueProof(publicKey kyber.Point, data []byte, proof []byte) (bool, error) {
	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Verify the data using Schnorr signature scheme and public key
	err := schnorr.Verify(suite, publicKey, data, proof)
	if err != nil {
		// If there is an error during verification, return false and the error
		return false, fmt.Errorf("failed to verify proof: %w", err)
	}

	// If there is no error, the proof is valid
	return true, nil
}
