# V2 VRF

In this we use a commitment (in this case, `RequestCommitmentV2Plus`) along with some randomness (provided by a Kyber scalar) to generate a unique proof. This proof is then used to generate a random number. The uniqueness of the random number in this context seems to rely on the uniqueness of the proof, which in turn depends on the unique combination of the commitment and the provided randomness.

Here's a flow in Go code that achieves this, using the Kyber library:

1.  Define the `RequestCommitmentV2Plus` structure and initialize it.
2.  Generate a proof using this structure and a random Kyber scalar.
3.  Use this proof to generate a unique random number.


But the problem is that the proof is not unique. The proof is generated using the `RequestCommitmentV2Plus` structure and a random Kyber scalar. The `RequestCommitmentV2Plus` structure is unique, and the random Kyber scalar is not unique. So the proof is not unique. The proof is not unique, so the random number is not unique.

Hence this can't be used as a VRF.

Since whenever we run the program with the same rc a new random Kyber scalar is generated and hence the proof is different.
and hence the random number is different.