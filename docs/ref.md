just an old reference code : )

```go 
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"math/big"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
    "github.com/ethereum/go-ethereum/common"
)


type Proof struct {
	PublicKey kyber.Point
	Gamma     kyber.Point
	C         kyber.Scalar
	S         kyber.Scalar
	Seed      kyber.Scalar
	Output    kyber.Scalar
}

type ReqCommit struct {
	BlockNum uint64
	SubId    uint64
	NumWords uint64
	Sender   string
}

type PodData struct {
	PodNumber uint64
	PodID     string
	Sender    string
}

// reference to the proof components
type VRFTypesProof struct {
	Pk            [2]*big.Int
	Gamma         [2]*big.Int
	C             *big.Int
	S             *big.Int
	Seed          *big.Int
	UWitness      common.Address
	CGammaWitness [2]*big.Int
	SHashWitness  [2]*big.Int
	ZInv          *big.Int
}
type VRFTypesRequestCommitment struct {
	BlockNum         uint64
	SubId            uint64
	CallbackGasLimit uint32
	NumWords         uint32
	Sender           common.Address
}


func old() {
	// Select the cryptographic suite you want to use
	suite := suites.MustFind("Ed25519")

	// Generate a new private key
	//private := suite.Scalar().Pick(suite.RandomStream())
	//fmt.Println("Private Key:", private)
	//
	//// Generate the corresponding public key
	//public := suite.Point().Mul(private, nil)

	privateKeyBytes, err := hex.DecodeString("c2dd063d14bb8a1950d5a244fccb5b865f19155e702a5f904e464c4da790f707")
	if err != nil {
		fmt.Printf("Error decoding private key: %v\n", err)
	}

	// Convert the byte slice into a Kyber scalar
	private := suite.Scalar().SetBytes(privateKeyBytes)
	public := suite.Point().Mul(private, nil)
	fmt.Println("Private Key :", private)
	fmt.Println("Public Key:", public)

	// pod data
	pod := PodData{
		PodNumber: 1234,
		PodID:     "id",
		Sender:    "air790128374987329487",
	}

	// Generate a seed from the struct data
	data := fmt.Sprintf("%d%s%s", pod.PodNumber, pod.PodID, pod.Sender)
	seedByte := sha256.Sum256([]byte(data))
	scalarSeed := suite.Scalar().SetBytes(seedByte[:])
	fmt.Println("Seed:", scalarSeed)

	// lets use pod number as nonce for demonstration
	// nonce
	buf := make([]byte, 8) // 8 bytes for uint64
	binary.BigEndian.PutUint64(buf, pod.PodNumber)
	podScaler := suite.Scalar().SetBytes(buf)
	fmt.Println("nonce:", podScaler)

	fmt.Println("generating proof...")
	// generate proof
	proof, err := GenerateProof(suite, scalarSeed, podScaler, private, public)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("proof:", proof)

	// verify proof
	fmt.Println("verify proof...")
	result, err := VerifyProof(suite, proof)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println("verify proof result:", result)

	// generate verifiable psudo random number

	// verify psudo random number

}

func fulfillRandomWords() {} // input proof, rc aka requestCommits

func GenerateProof(suite suites.Suite, seed, podScaler, privateKey kyber.Scalar, publicKey kyber.Point) (*model.Proof, error) {

	// HashToCurve operation
	h, err := HashToCurve(suite, publicKey, seed)
	if err != nil {
		fmt.Println("Error hashing to curve:", err)
		return nil, err
	}

	// Gamma = privateKey * H
	gamma := suite.Point().Mul(privateKey, h)

	// For demonstration, let's assume Generator is a base point
	uWitness := suite.Point().Mul(podScaler, suite.Point().Base())
	scalerWitness, err := pointToScalar(suite, uWitness)
	if err != nil {
		fmt.Println("Error converting point to scalar:", err)
		return nil, err

	}
	v := suite.Point().Mul(podScaler, h)

	// Assuming ScalarFromCurvePoints is a function you implement to derive a scalar from curve points
	c, err := ScalarFromCurvePoints(suite, h, publicKey, gamma, scalerWitness, v)
	if err != nil {
		return nil, err
	}

	// S calculation (s = podScaler - c*privateKey mod Group Order)
	// Note: You'll need to implement modular arithmetic operations according to your protocol
	s := suite.Scalar().Sub(podScaler, suite.Scalar().Mul(c, privateKey))

	// Output hash, for demonstration let's just reuse h as output
	output, err := pointToScalar(suite, h)
	if err != nil {
		fmt.Println("Error converting point to scalar:", err)
		return nil, err
	}

	proof := &Proof{
		PublicKey: publicKey,
		Gamma:     gamma,
		C:         c,
		S:         s,
		Seed:      seed,
		Output:    output, // This should be properly hashed as per your protocol
	}

	return proof, nil
}

func VerifyProof(suite suites.Suite, proof *Proof) (bool, error) {
	// Recompute h using HashToCurve with the PublicKey and Seed from the proof
	h, err := HashToCurve(suite, proof.PublicKey, proof.Seed)
	if err != nil {
		return false, fmt.Errorf("error recomputing h: %v", err)
	}

	// Recompute uWitness as s*G + c*PublicKey
	sG := suite.Point().Mul(proof.S, suite.Point().Base())
	cPK := suite.Point().Mul(proof.C, proof.PublicKey)
	uWitnessRecomputed := suite.Point().Add(sG, cPK)

	// Convert uWitness to scalar to compare with scalerWitness in proof
	scalerWitnessRecomputed, err := pointToScalar(suite, uWitnessRecomputed)
	if err != nil {
		return false, fmt.Errorf("error converting uWitness to scalar: %v", err)
	}

	// Recompute v as s*H + c*Gamma
	sH := suite.Point().Mul(proof.S, h)
	cGamma := suite.Point().Mul(proof.C, proof.Gamma)
	vRecomputed := suite.Point().Add(sH, cGamma)

	// Recalculate c from the recomputed values to ensure it matches the proof
	cRecomputed, err := ScalarFromCurvePoints(suite, h, proof.PublicKey, proof.Gamma, scalerWitnessRecomputed, vRecomputed)
	if err != nil {
		return false, fmt.Errorf("error recalculating c: %v", err)
	}

	// Ensure recomputed c matches the proof's c
	if !cRecomputed.Equal(proof.C) {
		return false, nil // c values do not match; proof is invalid
	}

	// If all checks pass, the proof is valid
	return true, nil
}

func HashToCurve(suite suites.Suite, publicKey kyber.Point, seed kyber.Scalar) (kyber.Point, error) {

	// First, serialize the public key and seed.
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	seedBytes, err := seed.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Concatenate the bytes and hash them.
	hasher := suite.Hash()

	_, err = hasher.Write(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(seedBytes)
	if err != nil {
		return nil, err
	}

	hashBytes := hasher.Sum(nil) // Final hash incorporating all inputs.

	// Convert the hash to a scalar
	xScalar := suite.Scalar().SetBytes(hashBytes)
	point := suite.Point().Mul(xScalar, nil) // 'nil' here means use the base point of the group

	return point, nil
}

func ScalarFromCurvePoints(suite suites.Suite, hash, pk, gamma kyber.Point, uWitnessScalar kyber.Scalar, v kyber.Point) (kyber.Scalar, error) {
	hasher := suite.Hash()

	// Process each point for hashing
	for _, point := range []kyber.Point{hash, pk, gamma, v} {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error marshaling point: %v", err)
		}
		_, err = hasher.Write(pointBytes)
		if err != nil {
			return nil, fmt.Errorf("error writing point to hasher: %v", err)
		}
	}

	// Marshal uWitnessScalar to bytes
	uWitnessBytes, err := uWitnessScalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshaling uWitness scalar: %v", err)
	}

	// Append uWitness scalar bytes and hash
	_, err = hasher.Write(uWitnessBytes)
	if err != nil {
		return nil, fmt.Errorf("error writing uWitness scalar to hasher: %v", err)
	}

	hashBytes := hasher.Sum(nil)
	scalar := suite.Scalar().SetBytes(hashBytes)

	return scalar, nil
}

func pointToScalar(suite suites.Suite, point kyber.Point) (kyber.Scalar, error) {
	// Marshal the point to a byte slice.
	pointBytes, err := point.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal point: %v", err)
	}

	// Hash the bytes to get a fixed-size output.
	hasher := suite.Hash()
	_, err = hasher.Write(pointBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash point bytes: %v", err)
	}
	hashBytes := hasher.Sum(nil)

	// Use the hash bytes to create a scalar.
	scalar := suite.Scalar().SetBytes(hashBytes)

	return scalar, nil
}

```