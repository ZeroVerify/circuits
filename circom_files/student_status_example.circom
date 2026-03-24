pragma circom 2.1.6;

include "poseidon.circom";
include "eddsa.circom";
include "comparators.circom";

template StudentStatus() {

    // ---------- Private Inputs ----------
    signal input subject_status;   // 1 = student
    signal input enrollment_status;
    signal input issued_at;
    signal input expires_at;

    signal input Ax;  // EdDSA public key
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;

    signal input subject_pseudonym;

    // ---------- Public Inputs ----------
    signal input challenge_nonce;
    signal input now;

    // ---------- Public Outputs ----------
    signal output out_nonce;
    signal output pseudonym_hash;

    // ---------- 1. Enrollment Check ----------
    enrollment_status === 1;

    // ---------- 2. Expiry Check ----------
    component gt = GreaterThan(64);
    gt.in[0] <== expires_at;
    gt.in[1] <== now;
    gt.out === 1; // expires_at must be > now

    // ---------- 3. Signature Verification ----------
    // Message = Poseidon(enrollment_status, issued_at, expires_at, subject_pseudonym)
    component msgHasher = Poseidon(4);
    msgHasher.inputs[0] <== enrollment_status;
    msgHasher.inputs[1] <== issued_at;
    msgHasher.inputs[2] <== expires_at;
    msgHasher.inputs[3] <== subject_pseudonym;

    // component verifier = EdDSA();
    // verifier.Ax <== Ax;
    // verifier.Ay <== Ay;
    // verifier.R8x <== R8x;
    // verifier.R8y <== R8y;
    // verifier.S   <== S;
    // verifier.M <== msgHasher.out;

    // ---------- 4. Outputs ----------
    out_nonce <== challenge_nonce;

    component pseudonymHasher = Poseidon(1);
    pseudonymHasher.inputs[0] <== subject_pseudonym;
    pseudonym_hash <== pseudonymHasher.out;
}

component main = StudentStatus();