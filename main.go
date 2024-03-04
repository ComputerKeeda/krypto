package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testingvrfbacktrack/vrf"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func main() {

	/*
		Private Key: 003de0dabc22c6b53d0e7bc34ec03eb4a2ac3991d5fa820ed613c000838f4d05
		Public Key: 4f7d61abd67bfad4400d454e7771b1e950c08d0272bc49588ea7d06fb773419d
	*/

	// Load the private key from a hexadecimal string
	privateKey, err := vrf.LoadHexPrivateKey("003de0dabc22c6b53d0e7bc34ec03eb4a2ac3991d5fa820ed613c000838f4d05")
	if err != nil {
		fmt.Printf("Error loading private key: %v\n", err)
		return
	}
	fmt.Printf("Private Key: %s\n", privateKey)

	// Derive the public key from the private key
	publicKey := vrf.GeneratePublicKey(privateKey)
	fmt.Printf("Public Key: %s\n", publicKey)

	fmt.Println("________________________________________________________________________________________________________________")

	// Initialize the RequestCommitmentV2Plus
	rc := vrf.RequestCommitmentV2Plus{
		BlockNum:         123456,
		StationId:        "Station12",
		UpperBound:       999999,
		RequesterAddress: "0x123456789abcdef",
		ExtraArgs:        0x01,
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Serialize the RequestCommitmentV2Plus instance
	serializedRC, err := vrf.SerializeRequestCommitmentV2Plus(rc)
	if err != nil {
		fmt.Printf("Error serializing RequestCommitmentV2Plus: %v\n", err)
		return
	}

	// Print out the serialized data in hexadecimal format
	fmt.Printf("Serialized RequestCommitmentV2Plus: %s\n", hex.EncodeToString(serializedRC))

	// Generate a unique proof using the private key and serialized data
	// proof, err := vrf.GenerateUniqueProof(suite, privateKey, serializedRC)
	// if err != nil {
	// 	fmt.Printf("Error generating unique proof: %v\n", err)
	// 	return
	// }
	proof, vrfOutput, err := vrf.GenerateVRFProof(suite, privateKey, serializedRC, int64(rc.BlockNum))
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
	valid, err := vrf.VerifyVRFProof(suite, publicKey, serializedRC, proof, int64(rc.BlockNum), vrfOutput)
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
	randomNumber, err := vrf.GenerateDeterministicRandomNumber(proof)
	if err != nil {
		fmt.Printf("Error generating deterministic random number: %v\n", err)
		return
	}

	// Convert the byte slice to a big.Int
	randomNumBigInt := new(big.Int).SetBytes(randomNumber)

	// Print out the deterministic random number in decimal format
	fmt.Printf("Deterministic Random Number (Decimal): %s\n", randomNumBigInt.String())
}
