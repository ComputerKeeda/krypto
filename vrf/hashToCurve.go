package vrf

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

func HashToCurve(publicKey kyber.Point, seed []byte) kyber.Point {
	// Hash the seed using SHA-256
	suite := suites.MustFind("Ed25519")
	preXNonSumHash := suite.Hash()
	var number int = 1
	byteSlice := []byte{byte(number)}
	preXNonSumHash.Write(byteSlice)
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	preXNonSumHash.Write(publicKeyBytes)
	preXNonSumHash.Write(seed)
	preX := preXNonSumHash.Sum(nil)

	// Convert the hashed seed to a Kyber scalar
	x := suite.Scalar().SetBytes(preX)

	// Generate a point on the curve using the seed
	point := suite.Point().Mul(x, publicKey)

	return point
}
