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

-   We convert the `randomNumber` (which is a byte slice) into a `big.Int` using `SetBytes`.
-   Then, we use the `String` method of the `big.Int` type to get the decimal representation of the number and print it.

This will output the deterministic random number in decimal format instead of hexadecimal.
