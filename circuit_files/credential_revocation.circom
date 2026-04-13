pragma circom 2.1.6;

include "eddsaposeidon.circom";

// CredentialRevocation proves that the prover holds a valid field signature
// issued by the credential authority for a specific credential. The credential_id
// is bound as a public input so the verifier can tie the proof to a known credential.
//
// Public signals (in order): [credential_id, Ax, Ay]
//   credential_id — SHA256(credentialID string) mod BabyJubJub SubOrder
//   Ax, Ay        — issuer BabyJubJub public key coordinates
//
// Private inputs:
//   field_hash    — SHA256(field_value) mod BabyJubJub SubOrder
//   R8x, R8y, S  — EdDSA signature components from the credential's fieldSignatures
template CredentialRevocation() {
    // ---------- Public Inputs ----------
    signal input credential_id;  // SHA256(credentialID) mod SubOrder
    signal input Ax;             // Issuer public key x-coordinate
    signal input Ay;             // Issuer public key y-coordinate

    // ---------- Private Inputs ----------
    signal input field_hash;    // SHA256(field_value) mod SubOrder
    signal input R8x;
    signal input R8y;
    signal input S;

    // ---------- Signature Verification ----------
    // Proves the prover holds a valid field signature from the issuer,
    // establishing ownership of the credential.
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax  <== Ax;
    sigVerifier.Ay  <== Ay;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.S   <== S;
    sigVerifier.M   <== field_hash;
}

component main {public [credential_id, Ax, Ay]} = CredentialRevocation();
