package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
)

type RequestCommitmentV2Plus struct {
	blockNum         uint64
	stationId        string
	upperBound       uint64
	requesterAddress string
	extraArgs        byte
}

func main() {
	// Initialize the RequestCommitmentV2Plus
	rc := RequestCommitmentV2Plus{
		blockNum:         123456,
		stationId:        "Station42",
		upperBound:       999999,
		requesterAddress: "0x123456789abcdef",
		extraArgs:        0x01,
	}

	// Initialize Kyber suite and generate randomness
	suite := edwards25519.NewBlakeSHA256Ed25519()
	randomScalar := suite.Scalar().Pick(random.New())

	// Generate the proof using the rc and the randomScalar
	proof, err := GenerateProof(suite, rc, randomScalar)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		return
	}

	// Use the proof to generate a unique random number
	randomNumber := GenerateRandomNumber(proof)

	fmt.Printf("Unique Random Number: %x\n", randomNumber)
}

// GenerateProof creates a proof based on the RequestCommitmentV2Plus and a Kyber scalar
func GenerateProof(suite kyber.Group, rc RequestCommitmentV2Plus, seed kyber.Scalar) ([]byte, error) {
	var buf bytes.Buffer

	// Encode the RequestCommitmentV2Plus into the buffer
	err := binary.Write(&buf, binary.BigEndian, rc.blockNum)
	if err != nil {
		return nil, err
	}
	buf.WriteString(rc.stationId)
	err = binary.Write(&buf, binary.BigEndian, rc.upperBound)
	if err != nil {
		return nil, err
	}
	buf.WriteString(rc.requesterAddress)
	buf.WriteByte(rc.extraArgs)

	// Convert the Kyber scalar (seed) into bytes and write it to the buffer
	seedBytes, err := seed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf.Write(seedBytes)

	// Create a SHA-256 hash of the buffer as the proof
	hash := sha256.Sum256(buf.Bytes())
	return hash[:], nil // Returning the proof as a byte slice
}

// GenerateRandomNumber generates a unique random number based on the proof
func GenerateRandomNumber(proof []byte) []byte {
	// For simplicity, we're just using another hash of the proof as the "unique" random number.
	// In a real-world application, you might want to use a more sophisticated method.
	randomNumber := sha256.Sum256(proof)
	return randomNumber[:]
}
