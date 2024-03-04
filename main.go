package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

type RequestCommitmentV2Plus struct {
	blockNum         uint64
	stationId        string
	upperBound       uint64
	requesterAddress string
	extraArgs        byte
}

// Function to serialize RequestCommitmentV2Plus into a deterministic byte slice
func SerializeRequestCommitmentV2Plus(rc RequestCommitmentV2Plus) ([]byte, error) {
	var buf bytes.Buffer

	// Encode the blockNum
	err := binary.Write(&buf, binary.BigEndian, rc.blockNum)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blockNum: %w", err)
	}

	// Encode the stationId as a fixed size or prefixed with its length
	// Here, we choose to prefix with length for simplicity
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(rc.stationId))); err != nil {
		return nil, fmt.Errorf("failed to encode stationId length: %w", err)
	}
	buf.WriteString(rc.stationId)

	// Encode the upperBound
	err = binary.Write(&buf, binary.BigEndian, rc.upperBound)
	if err != nil {
		return nil, fmt.Errorf("failed to encode upperBound: %w", err)
	}

	// Encode the requesterAddress as a fixed size or prefixed with its length
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(rc.requesterAddress))); err != nil {
		return nil, fmt.Errorf("failed to encode requesterAddress length: %w", err)
	}
	buf.WriteString(rc.requesterAddress)

	// Encode the extraArgs
	buf.WriteByte(rc.extraArgs)

	return buf.Bytes(), nil
}

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

func main() {
	// Initialize the Kyber suite for Edwards25519 curve
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate a new private key
	privateKey := suite.Scalar().Pick(suite.RandomStream())

	// Derive the public key from the private key
	publicKey := suite.Point().Mul(privateKey, nil)

	// Print out the public and private keys
	fmt.Printf("Private Key: %s\n", privateKey)
	fmt.Printf("Public Key: %s\n", publicKey)

	fmt.Println("________________________________________________________")

	// Initialize the RequestCommitmentV2Plus
	rc := RequestCommitmentV2Plus{
		blockNum:         123456,
		stationId:        "Station12",
		upperBound:       999999,
		requesterAddress: "0x123456789abcdef",
		extraArgs:        0x01,
	}

	// Serialize the RequestCommitmentV2Plus instance
	serializedRC, err := SerializeRequestCommitmentV2Plus(rc)
	if err != nil {
		fmt.Printf("Error serializing RequestCommitmentV2Plus: %v\n", err)
		return
	}

	// Print out the serialized data in hexadecimal format
	fmt.Printf("Serialized RequestCommitmentV2Plus: %s\n", hex.EncodeToString(serializedRC))

	// Generate a unique proof using the private key and serialized data
	proof, err := GenerateUniqueProof(privateKey, serializedRC)
	if err != nil {
		fmt.Printf("Error generating unique proof: %v\n", err)
		return
	}

	// Print out the generated proof in hexadecimal format
	fmt.Printf("Generated Proof: %s\n", hex.EncodeToString(proof))

	// Optionally, print the public key for verification purposes
	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		fmt.Printf("Error marshaling public key: %v\n", err)
		return
	}
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(pubKeyBytes))


	// Verify the generated proof using the public key
	valid, err := VerifyUniqueProof(publicKey, serializedRC, proof)
	if err != nil {
		fmt.Printf("Error verifying proof: %v\n", err)
		return
	}

	if valid {
		fmt.Println("Proof is valid.")
	} else {
		fmt.Println("Proof is invalid.")
	}
}
