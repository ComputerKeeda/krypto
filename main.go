package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testingvrfbacktrack/modules"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

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
	rc := modules.RequestCommitmentV2Plus{
		BlockNum:         123456,
		StationId:        "Station12",
		UpperBound:       999999,
		RequesterAddress: "0x123456789abcdef",
		ExtraArgs:        0x01,
	}

	// Serialize the RequestCommitmentV2Plus instance
	serializedRC, err := modules.SerializeRequestCommitmentV2Plus(rc)
	if err != nil {
		fmt.Printf("Error serializing RequestCommitmentV2Plus: %v\n", err)
		return
	}

	// Print out the serialized data in hexadecimal format
	fmt.Printf("Serialized RequestCommitmentV2Plus: %s\n", hex.EncodeToString(serializedRC))

	// Generate a unique proof using the private key and serialized data
	proof, err := modules.GenerateUniqueProof(privateKey, serializedRC)
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
	valid, err := modules.VerifyUniqueProof(publicKey, serializedRC, proof)
	if err != nil {
		fmt.Printf("Error verifying proof: %v\n", err)
		return
	}

	if valid {
		fmt.Println("Proof is valid.")
	} else {
		fmt.Println("Proof is invalid.")
	}

	// Generate a deterministic random number from the proof
	randomNumber, err := modules.GenerateDeterministicRandomNumber(proof)
	if err != nil {
		fmt.Printf("Error generating deterministic random number: %v\n", err)
		return
	}

	// Convert the byte slice to a big.Int
	randomNumBigInt := new(big.Int).SetBytes(randomNumber)

	// Print out the deterministic random number in decimal format
	fmt.Printf("Deterministic Random Number (Decimal): %s\n", randomNumBigInt.String())
}
