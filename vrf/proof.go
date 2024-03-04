package vrf

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

// Function to generate a unique proof using the private key and serialized data
func GenerateUniqueProof(suite *edwards25519.SuiteEd25519, privateKey kyber.Scalar, data []byte) ([]byte, error) {
	// Initialize the Kyber suite for Edwards25519 curve

	// Sign the data using Schnorr signature scheme and private key
	signature, err := schnorr.Sign(suite, privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// Function to generate a 'unique' (but insecure and deterministic) proof using the private key and serialized data
func GenerateInsecureDeterministicProof(suite kyber.Group, privateKey kyber.Scalar, data []byte, blockNumber int64) ([]byte, error) {
	// Generate a fixed, deterministic 'nonce' (insecurely)
	numBytes := big.NewInt(blockNumber).Bytes()

	// Convert the byte slice into a Kyber scalar
	nonce := suite.Scalar().SetBytes(numBytes)

	// Manually creating a Schnorr signature with a fixed nonce (This is for educational purposes only!)
	r := suite.Point().Mul(nonce, nil) // R = g^k where k is the nonce

	// Convert R to bytes
	rBytes, err := r.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal R: %w", err)
	}

	// Create a SHA-256 hash of R and the message
	h := sha256.New()
	h.Write(rBytes) // Hash R
	h.Write(data)   // Hash the message
	hashed := h.Sum(nil)

	e := suite.Scalar().SetBytes(hashed) // e = H(R || M)

	s := suite.Scalar().Mul(privateKey, e) // s = x * e
	s = suite.Scalar().Add(nonce, s)       // s = k + x * e (insecure!)

	// Convert s to bytes
	sBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal s: %w", err)
	}

	// Combine R and s into the signature: this is typically (R, s)
	signature := append(rBytes, sBytes...)

	return signature, nil
}

// Function to verify a unique proof using the public key, original data, and proof
func VerifyUniqueProof(suite *edwards25519.SuiteEd25519, publicKey kyber.Point, data []byte, proof []byte) (bool, error) {
	// Initialize the Kyber suite for Edwards25519 curve
	// suite := edwards25519.NewBlakeSHA256Ed25519()

	// Verify the data using Schnorr signature scheme and public key
	err := schnorr.Verify(suite, publicKey, data, proof)
	if err != nil {
		// If there is an error during verification, return false and the error
		return false, fmt.Errorf("failed to verify proof: %w", err)
	}

	// If there is no error, the proof is valid
	return true, nil
}

// func VerifyInsecureDeterministicProofX(suite kyber.Group, publicKey kyber.Point, data []byte, proof []byte, blockNumber int64) (bool, error) {
// 	// Split the proof back into R (the commitment) and s (the scalar)
// 	rBytes := proof[:suite.Point().MarshalSize()]
// 	sBytes := proof[suite.Point().MarshalSize():]

// 	// Unmarshal R and s from the proof
// 	r := suite.Point()
// 	err := r.UnmarshalBinary(rBytes)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to unmarshal R: %w", err)
// 	}

// 	s := suite.Scalar().SetBytes(sBytes)

// 	// Recreate the deterministic 'nonce' from blockNumber
// 	numBytes := big.NewInt(blockNumber).Bytes()
// 	nonce := suite.Scalar().SetBytes(numBytes)

// 	// Recompute e from R and the original data
// 	h := sha256.New()
// 	h.Write(rBytes) // Hash R
// 	h.Write(data)   // Hash the message
// 	hashed := h.Sum(nil)
// 	e := suite.Scalar().SetBytes(hashed)

// 	// Verify the equation R ?= g^s * y^-e
// 	// where g is the base point, y is the public key
// 	gs := suite.Point().Mul(nil, s)  // g^s
// 	ye := suite.Point().Mul(publicKey, e) // y^e
// 	yeInv := suite.Point().Neg(ye)        // -y^e
// 	expectedR := suite.Point().Add(gs, yeInv) // g^s * y^-e

// 	if !r.Equal(expectedR) {
// 		return false, fmt.Errorf("proof is invalid")
// 	}

// 	return true, nil
// }

func VerifyInsecureDeterministicProof(suite kyber.Group, publicKey kyber.Point, data []byte, proof []byte, blockNumber int64) (bool, error) {
	// Split the proof back into R (the commitment) and s (the scalar)
	rBytes := proof[:suite.Point().MarshalSize()]
	sBytes := proof[suite.Point().MarshalSize():]

	// Unmarshal R and s from the proof
	r := suite.Point()
	err := r.UnmarshalBinary(rBytes)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal R: %w", err)
	}

	s := suite.Scalar().SetBytes(sBytes)

	// Recreate the deterministic 'nonce' from blockNumber
	// numBytes := big.NewInt(blockNumber).Bytes()
	// nonce := suite.Scalar().SetBytes(numBytes)  // Note: this 'nonce' is not used in verification, only in signature generation.

	// Recompute e from R and the original data
	h := sha256.New()
	h.Write(rBytes) // Hash R
	h.Write(data)   // Hash the message
	hashed := h.Sum(nil)
	e := suite.Scalar().SetBytes(hashed)

	// Verify the equation R ?= g^s * y^-e
	// where g is the base point, y is the public key
	sPoint := ScalarToPoint(suite, s)
	gs := suite.Point().Mul(nil, sPoint) // g^s, where 'nil' represents the base point 'g'
	publicKeyScalar, err := PointToScalar(suite, publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key to scalar: %w", err)
	}
	ePoint := ScalarToPoint(suite, e)
	ye := suite.Point().Mul(publicKeyScalar, ePoint) // y^e, where 'y' is the public key
	yeInv := suite.Point().Neg(ye)                   // -y^e, inverse of y^e
	expectedR := suite.Point().Add(gs, yeInv)        // g^s * y^-e

	if !r.Equal(expectedR) {
		return false, fmt.Errorf("proof is invalid")
	}

	return true, nil
}

func ScalarToPoint(suite kyber.Group, scalar kyber.Scalar) kyber.Point {
	// Multiply the base point by the scalar to get a new point on the curve
	point := suite.Point().Mul(scalar, nil) // 'nil' here means use the base point of the group
	return point
}

func PointToScalar(suite kyber.Group, point kyber.Point) (kyber.Scalar, error) {
	// Convert the point to its binary representation
	pointBytes, err := point.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// You might use some bytes from the point to create a scalar,
	// for example, using the x-coordinate or hashing the entire point.
	// This is highly context-dependent and not standard cryptographic practice.
	scalar := suite.Scalar().SetBytes(pointBytes)
	return scalar, nil
}

func GenerateVRFProof(suite kyber.Group, privateKey kyber.Scalar, data []byte, nonce int64) ([]byte, []byte, error) {
	// Convert nonce to a deterministic scalar
	nonceBytes := big.NewInt(nonce).Bytes()
	nonceScalar := suite.Scalar().SetBytes(nonceBytes)

	// Generate proof like in a Schnorr signature: R = g^k, s = k + e*x
	R := suite.Point().Mul(nonceScalar, nil) // R = g^k
	hash := sha256.New()
	rBytes, _ := R.MarshalBinary()
	hash.Write(rBytes)
	hash.Write(data)
	e := suite.Scalar().SetBytes(hash.Sum(nil))                             // e = H(R||data)
	s := suite.Scalar().Add(nonceScalar, suite.Scalar().Mul(e, privateKey)) // s = k + e*x

	// The VRF output (pseudo-random value) is hash of R combined with data
	vrfHash := sha256.New()
	vrfHash.Write(rBytes)         // Incorporate R
	vrfHash.Write(data)           // Incorporate input data
	vrfOutput := vrfHash.Sum(nil) // This is the deterministic "random" output

	// Serialize R and s into the proof
	sBytes, _ := s.MarshalBinary()
	proof := append(rBytes, sBytes...)

	return proof, vrfOutput, nil
}

func VerifyVRFProof(suite kyber.Group, publicKey kyber.Point, data []byte, proof []byte, nonce int64, vrfOutput []byte) (bool, error) {
	// Deserialize R and s from the proof
	pointSize := suite.Point().MarshalSize()
	R, s := suite.Point(), suite.Scalar()
	R.UnmarshalBinary(proof[:pointSize])
	s.SetBytes(proof[pointSize:])

	// Recompute e = H(R||data) from the proof and data
	hash := sha256.New()
	rBytes, _ := R.MarshalBinary()
	hash.Write(rBytes)
	hash.Write(data)
	e := suite.Scalar().SetBytes(hash.Sum(nil))

	// Verify the equation R == g^s * y^-e
	fmt.Println("Check")
	// Verify the equation R == g^s * y^-e
	gs := suite.Point().Mul(s, nil) // g^s, correct usage
	// ye := suite.Point().Mul(publicKey, e)     // y^e, correct usage

	// Correct calculation for y^e where 'y' is publicKey (a point) and 'e' is a scalar.
	ye := suite.Point().Mul(e, publicKey)

	yeInv := suite.Point().Neg(ye)            // -y^e, correct usage
	expectedR := suite.Point().Add(gs, yeInv) // g^s * y^-e, correct combination

	if !R.Equal(expectedR) {
		return false, fmt.Errorf("invalid VRF proof")
	}

	// Verify the VRF output matches the hash of R and data
	vrfHash := sha256.New()
	vrfHash.Write(rBytes)
	vrfHash.Write(data)
	expectedVrfOutput := vrfHash.Sum(nil)
	if !bytes.Equal(vrfOutput, expectedVrfOutput) {
		return false, fmt.Errorf("invalid VRF output")
	}

	return true, nil
}
