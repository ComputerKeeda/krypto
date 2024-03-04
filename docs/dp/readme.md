# Deterministic Proof

So what happens when we have a deterministic proof? Well, we can use the same proof to prove the same statement over and over again. This is useful for things like smart contracts, where we want to be able to prove that a contract is valid and that it will always be valid. This is also useful for things like digital signatures, where we want to be able to prove that a signature is valid and that it will always be valid.

Now what was happening in our previous codes

i passed this values 2 times

```shell
Private Key: 003de0dabc22c6b53d0e7bc34ec03eb4a2ac3991d5fa820ed613c000838f4d05
Public Key: 4f7d61abd67bfad4400d454e7771b1e950c08d0272bc49588ea7d06fb773419d
________________________________________________________
Serialized RequestCommitmentV2Plus: 000000000001e240000000000000000953746174696f6e313200000000000f423f0000000000000011307831323334353637383961626364656601
```

on the 1st attempt i got this proof

```shell
Generated Proof: de64edabfe0dbbd3960e4d7796ace11ab39fa6f2fe695f18c3fff436e122d3a6b4cf586353bf55b2c637e24db5256093045a2d0e16de878c2b674cd49baf8d0e
```

and on the 2nd attempt i got

```shell
Generated Proof: 634c223d0c4a11f8eb0c5854ec1569fe118e8909a111cfa471d7ac99b9f637b3f1543daa8ec2c9715c6c6ae7ba482588a7ae8f8d06ca871598df84217776d902
```

## Reason

The difference in the generated proofs despite using the same input parameters (private key and serialized data) typically arises from additional randomness introduced during the proof generation process, especially in cryptographic schemes designed to enhance security and privacy.

> In the context of digital signatures and proofs, like those generated using the Schnorr scheme or similar cryptographic protocols, the generation process usually incorporates a random component (often referred to as a nonce) to ensure that each signature (or proof) is unique, even for the same message and the same private key. This property is crucial for preventing certain types of attacks and for enhancing the overall security of the cryptographic scheme.
>
> However, if you require deterministic outputs (i.e., the same input always produces the same output), you would need to modify the proof generation process to eliminate the randomness. This approach is typically not recommended for actual signature schemes due to security concerns, but it can be used in specific contexts like Verifiable Random Functions (VRFs).
>
> Since the standard Schnorr signature (or similar schemes used in your examples) typically includes randomness for each signature, getting different proofs for the same inputs is expected behavior.
>
> If you are attempting to implement a VRF, the key aspect is that the output should be deterministic based on the input and the private key, but the proof (or the signature part of the VRF) will typically include some randomness unless specifically designed to be deterministic.

For actual cryptographic applications, especially those needing verifiable randomness tied to a unique, unchangeable input, the varying proofs are not an issue as long as they can be:

1. Verified using the corresponding public key. The proofs should be verifiable by anyone holding the public key, ensuring the proof's authenticity and origin.

2. Used to derive the same deterministic output (random number) when passing through a final deterministic process (like hashing). In VRFs, while the proofs (or signatures) might differ due to incorporated randomness, the final output --- the deterministic random number derived from the proof --- should serve the intended use-case, ensuring that the process remains secure and verifiable.

If your implementation requires absolutely no variation in the cryptographic output for the same set of inputs (which goes beyond typical VRF usage and into pure deterministic signing), you would need to adapt the process to remove any random elements, which is generally not advised without a thorough security review.

In practice, for VRFs and similar cryptographic constructs, it's the final output (the deterministic part derived from the proof) that matters for consistency and verifiability, not the intermediate proofs themselves, which can vary with each execution. If your application requires deterministic proofs (not just deterministic final outputs), you would likely need a different approach or customization, which could compromise security and would need careful consideration.

Here is the function which was used to generate the proof

```go
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
```

The behavior you're encountering is typical for cryptographic signatures, including those generated using the Schnorr scheme. Even when the input (the private key and data) remains constant, the output (the signature or "proof") can differ between executions. **This variability is due to the inclusion of a random component in the signature generation process**, which is essential for security, particularly to prevent certain types of attacks.

In the case of Schnorr signatures and many other digital signature schemes, a unique random value (often referred to as a nonce) is generated during each signing process. This nonce ensures that each signature is unique, even if the same data and private key are used repeatedly. The randomness is crucial for ensuring the signature's security, as predictable signatures can be vulnerable to cryptographic attacks.

Here's how it works in the context of your function `GenerateUniqueProof`:

-   When `schnorr.Sign` is called, it internally generates a random scalar (the nonce) for each execution. This is part of the cryptographic security measures implemented by the Kyber library and the Schnorr signature algorithm.
-   This means that even if the private key and the data remain the same, the signature (proof) will differ between calls due to this random scalar.
-   Despite the signatures being different, any of them can still be verified with the corresponding public key and original data. The verification process will confirm the authenticity of the signature regardless of the specific nonce used during its creation.

The variability in the output does not impact the validity or the security of the signatures; in fact, it enhances security by ensuring that each signature is unique and cannot be reused or replayed. This is a standard and expected behavior in cryptographic systems.

If your application requires generating the same output for the same input, typically, you would use a hash function directly instead of a signature scheme. However, for cryptographic proof purposes where a signature is necessary, this variability is a feature, not a bug.

## Solution

**for some specific non-security-related reason** you need to generate a deterministic output from the same inputs (which is not typical or recommended for digital signatures), you would typically not use a signature scheme like Schnorr directly. Instead, you might consider deterministic cryptographic operations that do not incorporate internal randomness, such as certain types of **hash functions or deterministic encryption schemes**. But keep in mind, this removes the security properties provided by the randomness in digital signatures.

In the realm of cryptographic signatures, creating a deterministic signature (which is not standard practice) would involve using a fixed nonce rather than a random one. This is generally not recommended because it can lead to serious security vulnerabilities, especially if the same nonce is used across different messages or if the nonce can be guessed by an attacker.

If your application requires reproducibility for non-security-related features (like generating deterministic IDs or codes based on fixed inputs), you should use standard cryptographic hash functions (like SHA-256) directly on your inputs. This approach provides a deterministic output for the same input but should not be used as a substitute for a digital signature where authenticity and non-repudiation are required.

If your use case is strictly for purposes other than security (such as generating a deterministic identifier or some form of deterministic encryption that does not need to be secure against all the threats that digital signatures protect against), and you understand the risks, you could theoretically modify the signature generation to use a fixed value instead of a random one. However, I must stress that this approach is hazardous if the data needs to be secured or authenticated in a way that relies on the unpredictability of the signature.

Since modifying cryptographic procedures can severely weaken security, it's crucial to clarify why you seek deterministic behavior from a process inherently designed to be non-deterministic. If you're dealing with a scenario that doesn't require the security properties of a signature, consider whether other cryptographic or even non-cryptographic methods might meet your needs more appropriately.