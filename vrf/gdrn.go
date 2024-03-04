package vrf

import "crypto/sha256"

// Function to generate a deterministic random number from a proof
func GenerateDeterministicRandomNumber(proof []byte) ([]byte, error) {
	// Apply a SHA-256 hash to the proof to generate the random number
	hash := sha256.Sum256(proof)
	return hash[:], nil
}
