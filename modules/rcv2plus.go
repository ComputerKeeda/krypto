package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type RequestCommitmentV2Plus struct {
	BlockNum         uint64
	StationId        string
	UpperBound       uint64
	RequesterAddress string
	ExtraArgs        byte
}

// Function to serialize RequestCommitmentV2Plus into a deterministic byte slice
func SerializeRequestCommitmentV2Plus(rc RequestCommitmentV2Plus) ([]byte, error) {
	var buf bytes.Buffer

	// Encode the blockNum
	err := binary.Write(&buf, binary.BigEndian, rc.BlockNum)
	if err != nil {
		return nil, fmt.Errorf("failed to encode blockNum: %w", err)
	}

	// Encode the stationId as a fixed size or prefixed with its length
	// Here, we choose to prefix with length for simplicity
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(rc.StationId))); err != nil {
		return nil, fmt.Errorf("failed to encode stationId length: %w", err)
	}
	buf.WriteString(rc.StationId)

	// Encode the upperBound
	err = binary.Write(&buf, binary.BigEndian, rc.UpperBound)
	if err != nil {
		return nil, fmt.Errorf("failed to encode upperBound: %w", err)
	}

	// Encode the requesterAddress as a fixed size or prefixed with its length
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(rc.RequesterAddress))); err != nil {
		return nil, fmt.Errorf("failed to encode requesterAddress length: %w", err)
	}
	buf.WriteString(rc.RequesterAddress)

	// Encode the extraArgs
	buf.WriteByte(rc.ExtraArgs)

	return buf.Bytes(), nil
}
