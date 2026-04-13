pragma circom 2.1.6;

include "poseidon.circom";
include "eddsaposeidon.circom";
include "comparators.circom";

template StudentStatus() {

    // ---------- Private Inputs ----------
    signal input subject_pseudonym;
    signal input enrollment_status;   // field element: SHA256("student") mod BabyJubJub SubOrder
    signal input issued_at;           // Unix timestamp
    signal input expires_at;          // Unix timestamp

    signal input Ax;  // EdDSA public key x-coordinate
    signal input Ay;  // EdDSA public key y-coordinate
    signal input R8x;
    signal input R8y;
    signal input S;

    // ---------- Public Inputs ----------
    signal input challenge_nonce;
    signal input now;                 // Unix timestamp, supplied by verifier

    // ---------- Public Outputs ----------
    signal output out_nonce;
    signal output pseudonym_hash;

    // ---------- 1. Enrollment Check ----------
    // 906954226396135619011145686687621910857321037597927521422477382836222528533
    // = SHA256("student") mod BabyJubJub SubOrder
    var ENROLLMENT_STATUS_STUDENT = 906954226396135619011145686687621910857321037597927521422477382836222528533;
    enrollment_status === ENROLLMENT_STATUS_STUDENT;

    // ---------- 2. Time Window Check ----------
    // now must be >= issued_at
    component geIssued = GreaterEqThan(64);
    geIssued.in[0] <== now;
    geIssued.in[1] <== issued_at;
    geIssued.out === 1;

    // now must be < expires_at
    component ltExpiry = GreaterThan(64);
    ltExpiry.in[0] <== expires_at;
    ltExpiry.in[1] <== now;
    ltExpiry.out === 1;

    // ---------- 3. Credential Message Hash ----------
    // Message = Poseidon(subject_pseudonym, enrollment_status, issued_at, expires_at)
    component msgHasher = Poseidon(4);
    msgHasher.inputs[0] <== subject_pseudonym;
    msgHasher.inputs[1] <== enrollment_status;
    msgHasher.inputs[2] <== issued_at;
    msgHasher.inputs[3] <== expires_at;

    // ---------- 4. EdDSA Signature Verification ----------
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax  <== Ax;
    verifier.Ay  <== Ay;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S   <== S;
    verifier.M   <== msgHasher.out;

    // ---------- 5. Outputs ----------
    out_nonce <== challenge_nonce;

    component pseudonymHasher = Poseidon(1);
    pseudonymHasher.inputs[0] <== subject_pseudonym;
    pseudonym_hash <== pseudonymHasher.out;
}

component main {public [challenge_nonce, now]} = StudentStatus();
