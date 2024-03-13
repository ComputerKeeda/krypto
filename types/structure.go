package types

import (
	"go.dedis.ch/kyber/v3"
	"math/big"
)

type Proof struct {
	Pk            [2]*big.Int
	Gamma         [2]*big.Int
	C             *big.Int
	S             *big.Int
	Seed          *big.Int
	Output        kyber.Scalar
	CGammaWitness [2]*big.Int
	SHashWitness  [2]*big.Int
	ZInv          *big.Int
}

type RequestCommitmentV2Plus struct {
	PodNumber        uint64
	StationId        string
	UpperBound       uint64
	RequesterAddress string
	ExtraArgs        byte
}
