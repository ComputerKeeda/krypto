# V3 VRF

In the context of a VRF using Kyber, we'd typically do the following:

1. Use the holder's private key and public key in the process.
2. Combine your `RequestCommitmentV2Plus` structure into a deterministic input.
3. Use the private key to generate a unique proof (which is different from just hashing as it involves cryptographic operations ensuring that only the key holder can generate this proof).
4. Verify the proof with the corresponding public key to ensure authenticity.
5. From this proof, generate a deterministic random number (output).

The deterministic nature comes from the fact that for the same input and the same private key, the output (the proof and hence the random number) will always be the same.

## Step 1: Generate a private key and public key

we'll start by creating the holder's private key and public key using the Kyber library, specifically within the Edwards25519 elliptic curve group context, which is commonly used for these operations. I'll guide you through the Go code required to achieve this.

```go
package main

import (
 "fmt"
 "go.dedis.ch/kyber/v3"
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
}
```

This code does the following:

- It initializes a cryptographic suite for the Edwards25519 elliptic curve. This suite provides the necessary cryptographic operations for this curve.

- It generates a new private key by picking a random scalar from the group defined by the Edwards25519 curve. In cryptographic terms, a scalar typically represents a private key.

- It derives the public key from the private key. In elliptic curve cryptography, the public key is typically the result of multiplying the private key (a scalar) with the curve's base point (a predefined point on the curve).

- It prints out the private and public keys so you can see the result.

This is the first step in creating a VRF (Verifiable Random Function) using Kyber.

## Step 2: Combine your `RequestCommitmentV2Plus` structure into a deterministic input

Great, moving on to the second step: Combining your RequestCommitmentV2Plus structure into a deterministic input. This involves serializing the fields of your structure into a byte array in a way that is deterministic, meaning that the same structure will always result in the same byte array. This process is crucial for ensuring that the input to the cryptographic operations is consistent and reproducible.

Here's how you can modify your code to serialize the RequestCommitmentV2Plus structure:

```go
package main

import (
 "bytes"
 "encoding/binary"
 "fmt"
)

// Assuming the RequestCommitmentV2Plus struct is defined as before
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

// Add the rest of your existing main function here, if needed
```

In this code:

- We serialize each field of RequestCommitmentV2Plus into a bytes.Buffer.
- Numeric fields like blockNum and upperBound are encoded in big-endian format, which is a common choice for network protocols and cryptographic operations as it preserves numerical ordering.
- For strings like stationId and requesterAddress, we first write their length (as a uint64) and then the string itself. This is a standard way to encode variable-length strings to ensure that they can be correctly parsed back from the byte stream.
- Finally, extraArgs (a single byte) is appended directly.
  
This serialized output can then be used as deterministic input for cryptographic operations.

>here's a sample main function that uses the SerializeRequestCommitmentV2Plus function to serialize a RequestCommitmentV2Plus instance. This example will create an instance of your structure, serialize it, and then print out the resulting byte array in hexadecimal format for verification:
>
> ```go
> package main
> 
> import (
>  "encoding/hex"
>  "fmt"
> )
> 
> func main() {
>  // Initialize the RequestCommitmentV2Plus
>  rc := RequestCommitmentV2Plus{
>   blockNum:         123456,
>   stationId:        "Station42",
>   upperBound:       999999,
>   requesterAddress: "0x123456789abcdef",
>   extraArgs:        0x01,
>  }
> 
>  // Serialize the RequestCommitmentV2Plus instance
>  serializedRC, err := SerializeRequestCommitmentV2Plus(rc)
>  if err != nil {
>   fmt.Printf("Error serializing RequestCommitmentV2Plus: %v\n", err)
>   return
>  }
> 
>  // Print out the serialized data in hexadecimal format
>  fmt.Printf("Serialized RequestCommitmentV2Plus: %s\n", hex.EncodeToString(serializedRC))
> }
> ```
>
> In this main function:
>
> 1. A RequestCommitmentV2Plus instance rc is created with some sample data.
> 2. The SerializeRequestCommitmentV2Plus function is called with rc as the argument to serialize it into a byte slice.
> 3. If there's no error, the serialized byte slice is encoded into a hexadecimal string using hex.EncodeToString and printed out.
>
> You can run this code to see the hexadecimal representation of the serialized RequestCommitmentV2Plus structure. This is a useful format for debugging and verifying that your serialization works as expected.

## Step 3: Use the private key to generate a unique proof

we will use the holder's private key to generate a unique proof. This involves cryptographic operations that ensure only the key holder can generate this proof, leveraging the properties of the Kyber library. We'll assume you're working with the Edwards25519 curve provided by the Kyber library for these operations.

First, ensure you have the Kyber library properly imported and ready for use. Then, we will create a function that takes a private key, the serialized RequestCommitmentV2Plus, and generates a unique cryptographic proof. This will involve signing the serialized data, which is a common approach to generating such proofs.

Here's how you can do this:

```go
package main

import (
 "fmt"
 "go.dedis.ch/kyber/v3"
 "go.dedis.ch/kyber/v3/group/edwards25519"
 "go.dedis.ch/kyber/v3/sign/schnorr"
)

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

// Your existing code for main function, RequestCommitmentV2Plus struct, and serialization function
```

In this code snippet:

- We define a new function GenerateUniqueProof that takes a private key of type kyber.Scalar and a byte slice data (which should be your serialized RequestCommitmentV2Plus structure).
- We use the edwards25519.NewBlakeSHA256Ed25519 suite from the Kyber library, which sets up the cryptographic environment using the Edwards25519 elliptic curve and the BlakeSHA256 hash function.
- We then use the Schnorr signing method provided by Kyber to sign the data with the private key. The Schnorr signature scheme is known for its simplicity and security.

Note: This assumes you already have a private key generated. Typically, in a real-world application, this private key would be securely stored and managed. For testing purposes, you can generate a new private key using Kyber, but in actual usage, this key should be securely generated and stored beforehand.

> example of how you could modify your main function to test the GenerateUniqueProof function. This includes generating a private and public key pair, serializing the RequestCommitmentV2Plus structure, and then using the private key to generate a unique proof:
>
> ```go
> package main
> 
> import (
>  "encoding/hex"
>  "fmt"
>  "go.dedis.ch/kyber/v3"
>  "go.dedis.ch/kyber/v3/group/edwards25519"
>  "go.dedis.ch/kyber/v3/sign/schnorr"
>  "go.dedis.ch/kyber/v3/util/random"
> )
> 
> func main() {
>  // Initialize the Kyber suite for Edwards25519 curve
>  suite := edwards25519.NewBlakeSHA256Ed25519()
> 
>  // Generate a private and public key pair
>  privateKey := suite.Scalar().Pick(random.New())
>  publicKey := suite.Point().Mul(privateKey, nil)
> 
>  // Initialize the RequestCommitmentV2Plus
>  rc := RequestCommitmentV2Plus{
>   blockNum:         123456,
>   stationId:        "Station42",
>   upperBound:       999999,
>   requesterAddress: "0x123456789abcdef",
>   extraArgs:        0x01,
>  }
> 
>  // Serialize the RequestCommitmentV2Plus instance
>  serializedRC, err := SerializeRequestCommitmentV2Plus(rc)
>  if err != nil {
>   fmt.Printf("Error serializing RequestCommitmentV2Plus: %v\n", err)
>   return
>  }
> 
>  // Generate a unique proof using the private key and serialized data
>  proof, err := GenerateUniqueProof(privateKey, serializedRC)
>  if err != nil {
>   fmt.Printf("Error generating unique proof: %v\n", err)
>   return
>  }
> 
>  // Print out the generated proof in hexadecimal format
>  fmt.Printf("Generated Proof: %s\n", hex.EncodeToString(proof))
> 
>  // Optionally, print the public key for verification purposes
>  pubKeyBytes, err := publicKey.MarshalBinary()
>  if err != nil {
>   fmt.Printf("Error marshaling public key: %v\n", err)
>   return
>  }
>  fmt.Printf("Public Key: %s\n", hex.EncodeToString(pubKeyBytes))
> }
> ```
>
> In this main function:
>
> - We initialize the cryptographic suite using the Edwards25519 curve.
> - We generate a new private key and corresponding public key.
> - We initialize your RequestCommitmentV2Plus structure and serialize it.
> - We call GenerateUniqueProof with the private key and the serialized data to create the proof.
> - We print out the generated proof in hexadecimal format for inspection.
> - Optionally, we also print out the public key in hexadecimal format. This could be useful if you want to verify the proof elsewhere.
>
> You can run this main function to see the generated proof and public key.

## Step 4: Verify the proof with the corresponding public key

To verify the proof with the corresponding public key and ensure the authenticity of the signed data (in this case, the serialized `RequestCommitmentV2Plus`), we will create a new function `VerifyUniqueProof`. This function will take the public key, the original data (should be the same data used for generating the proof), and the proof itself. It will return a boolean indicating whether the proof is valid.

Here's how you can do this:

```go
package main

import (
 "fmt"
 "go.dedis.ch/kyber/v3"
 "go.dedis.ch/kyber/v3/sign/schnorr"
)

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
```

In this code snippet:

- We define a new function `VerifyUniqueProof` that takes a public key of type `kyber.Point`, a byte slice `data`, and a byte slice `proof`.
- We use the `schnorr.Verify` method from the Kyber library to verify the proof against the data and public key.
- If the verification is successful (no error is returned), the proof is considered valid, and the function returns `true`.
- If there is any error during verification, the proof is considered invalid, and the function returns `false` along with the error.

Now, let's integrate this verification step into the `main` function or another suitable place in your program to test it:

```go
func main() {
 // ... (previous code for generating keys, serializing data, and creating proof)

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

 // ... (any additional code)
}
```

In this part of the `main` function:

- We call `VerifyUniqueProof` with the public key, the serialized data, and the generated proof.
- We check the result and print out whether the proof is valid.

This will complete the verification process.


