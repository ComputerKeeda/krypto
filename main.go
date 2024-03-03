package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/random"
)

func main() {
	// Use the edwards25519-curve
	suite := suites.MustFind("Ed25519").(*edwards25519.SuiteEd25519)

	// Generate Bob's private key
	privateKey := suite.Scalar().Pick(suite.RandomStream())

	// Generate Bob's public key (by multiplying the base point with the private key)
	publicKey := suite.Point().Mul(privateKey, nil)

	// Print the keys to check
	fmt.Printf("Private Key: %s\n", privateKey)
	fmt.Printf("Public Key: %s\n", publicKey)

	// Example of signing a message using the private key
	// Note: In a real application, you should hash the message before signing it
	message := []byte("Hello, world!")
	signature, error := Sign(suite, privateKey, message)
	if error != nil {
		fmt.Println("Error signing the message:", error)
	} else {
		fmt.Printf("Signature: %x\n", signature)
	}

	// Verify the signature with the public key
	err := Verify(suite, publicKey, message, signature)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
	} else {
		fmt.Println("Signature verified successfully!")
	}
}

// Sign creates a signature of a message given a private key
func Sign(suite kyber.Group, privateKey kyber.Scalar, message []byte) ([]byte, error) {
	// Use Go's crypto/rand for cryptographic randomness
	randomStream := random.New(rand.Reader)

	// Create a temporary scalar (k) and its corresponding point (R = k * G)
	k := suite.Scalar().Pick(randomStream)
	R := suite.Point().Mul(k, nil)

	// Convert R to bytes
	rBytes, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Hash the concatenation of R and the message using SHA-256
	h := sha256.New()
	h.Write(rBytes)  // Write R in bytes
	h.Write(message) // Write the message
	hash := h.Sum(nil)

	// Convert the hash to a scalar
	e := suite.Scalar().SetBytes(hash)

	// Compute the signature s = k - e * privateKey
	s := suite.Scalar().Sub(k, suite.Scalar().Mul(e, privateKey))

	// Convert s to bytes
	sBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Return R and s concatenated
	signature := append(rBytes, sBytes...)
	return signature, nil
}

// Verify checks the signature of a message given the public key
func Verify(suite kyber.Group, publicKey kyber.Point, message []byte, signature []byte) error {
	// Split the signature into R and s
	pointSize := publicKey.MarshalSize()
	if len(signature) < pointSize {
		return fmt.Errorf("signature too short")
	}
	R := suite.Point()
	err := R.UnmarshalBinary(signature[:pointSize])
	if err != nil {
		return fmt.Errorf("failed to unmarshal R: %v", err)
	}
	s := suite.Scalar().SetBytes(signature[pointSize:])

	// Convert R to bytes for hashing
	rBytes, err := R.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal R: %v", err)
	}

	// Hash the concatenation of R and the message using SHA-256
	h := sha256.New()
	h.Write(rBytes)  // Write R in bytes
	h.Write(message) // Write the message
	hash := h.Sum(nil)

	// Convert the hash to a scalar
	e := suite.Scalar().SetBytes(hash)

	// Check that sG + eY == R
	sG := suite.Point().Mul(s, nil)       // s * G
	eY := suite.Point().Mul(e, publicKey) // e * publicKey
	sG.Add(sG, eY)                        // sG + eY

	// Check if the computed point is equal to R
	if !R.Equal(sG) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// package main

// import "go.dedis.ch/kyber/v3/suites"

// func main() {
// 	suite := suites.MustFind("Ed25519")            // Use the edwards25519-curve
// 	privateKey := suite.Scalar().Pick(suite.RandomStream()) // Bob's private key
// 	publicKey := suite.Point().Mul(a, nil)                 // Bob's public key
// }
