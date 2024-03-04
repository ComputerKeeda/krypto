package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"go.dedis.ch/kyber/v3/group/edwards25519"
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
}
