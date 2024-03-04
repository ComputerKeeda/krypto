# VRF

To print the deterministic random number in decimal format, you will need to convert the byte array (which represents the number) into an integer. In Go, you can use the `big.Int` type from the `math/big` package to handle large integers that may result from cryptographic operations.

Here's how you can modify your code to print the deterministic random number in decimal format:

```go
package main

import (
 "crypto/sha256"
 "fmt"
 "math/big"
)

func main() {
 // ... (previous code for generating keys, serializing data, creating and verifying proof)

 // Generate a deterministic random number from the proof
 randomNumber, err := GenerateDeterministicRandomNumber(proof)
 if err != nil {
  fmt.Printf("Error generating deterministic random number: %v\n", err)
  return
 }

 // Convert the byte slice to a big.Int
 randomNumBigInt := new(big.Int).SetBytes(randomNumber)

 // Print out the deterministic random number in decimal format
 fmt.Printf("Deterministic Random Number (Decimal): %s\n", randomNumBigInt.String())

 // ... (any additional code)
}
```

In this modified part of the `main` function:

- We convert the `randomNumber` (which is a byte slice) into a `big.Int` using `SetBytes`.
- Then, we use the `String` method of the `big.Int` type to get the decimal representation of the number and print it.

This will output the deterministic random number in decimal format instead of hexadecimal.

## Load Stored Private Key and Public Key in the VRF

To convert a hexadecimal representation of a private key into a `kyber.Scalar` object using the Kyber library, you will first need to decode the hexadecimal string into a byte slice. Then, you can use the `SetBytes` method of the `kyber.Scalar` to convert the byte slice into a scalar. Here's how you can do it in your Go code:

```go
package main

import (
 "encoding/hex"
 "fmt"
 "go.dedis.ch/kyber/v3"
 "go.dedis.ch/kyber/v3/group/edwards25519"
)

func main() {
 // Your provided private key in hexadecimal format
 privateKeyHex := "003de0dabc22c6b53d0e7bc34ec03eb4a2ac3991d5fa820ed613c000838f4d05"

 // Convert the hexadecimal string to a byte slice
 privateKeyBytes, err := hex.DecodeString(privateKeyHex)
 if err != nil {
  fmt.Printf("Error decoding private key: %v\n", err)
  return
 }

 // Initialize the Kyber suite for Edwards25519 curve
 suite := edwards25519.NewBlakeSHA256Ed25519()

 // Convert the byte slice into a Kyber scalar
 privateKey := suite.Scalar().SetBytes(privateKeyBytes)

 // Now you can use privateKey with the rest of your cryptographic operations
 // For example, generating a unique proof (you would need to add the rest of the relevant code here)

 // Just a placeholder for where you would use the private key, such as generating a proof
 // proof, err := GenerateUniqueProof(privateKey, yourDataHere)
 // if err != nil {
 //     fmt.Printf("Error generating unique proof: %v\n", err)
 //     return
 // }
 // fmt.Printf("Generated Proof: %x\n", proof)

 // ... (any additional code)
}
```

In this code:

- `privateKeyHex` is your private key in hexadecimal format.
- `hex.DecodeString` converts the hexadecimal string to a byte slice.
- `suite.Scalar().SetBytes(privateKeyBytes)` converts the byte slice into a Kyber scalar.
- You can then use this `privateKey` scalar in cryptographic operations, like generating a unique proof.

Make sure to replace `"yourDataHere"` with the actual data you want to use for generating the proof, and include any other logic you need for your application.
