#!/usr/bin/env node

const crypto = require('crypto');
const { buildEddsa, buildPoseidon } = require('circomlibjs');
const fs = require('fs');
const path = require('path');

const BABY_JUB_SUB_ORDER = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');

function fieldElement(value) {
    const hash = crypto.createHash('sha256').update(value, 'utf8').digest();
    return BigInt('0x' + hash.toString('hex')) % BABY_JUB_SUB_ORDER;
}

async function generateStudentStatusInputs() {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;

    const privKey = Buffer.from(
        '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        'hex'
    );
    const pubKey = eddsa.prv2pub(privKey);

    const subjectPseudonymHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const subjectPseudonymFE = BigInt('0x' + subjectPseudonymHex) % BABY_JUB_SUB_ORDER;

    const enrollmentStatusFE = fieldElement('student');
    const issuedAt = BigInt(1700000000);
    const expiresAt = BigInt(9999999999);
    const now = BigInt(1700000001);

    const msgHash = poseidon([subjectPseudonymFE, enrollmentStatusFE, issuedAt, expiresAt]);

    const sig = eddsa.signPoseidon(privKey, msgHash);

    return {
        subject_pseudonym: subjectPseudonymFE.toString(),
        enrollment_status: enrollmentStatusFE.toString(),
        issued_at: issuedAt.toString(),
        expires_at: expiresAt.toString(),
        Ax: F.toObject(pubKey[0]).toString(),
        Ay: F.toObject(pubKey[1]).toString(),
        R8x: F.toObject(sig.R8[0]).toString(),
        R8y: F.toObject(sig.R8[1]).toString(),
        S: sig.S.toString(),
        challenge_nonce: '42',
        now: now.toString(),
    };
}

async function main() {
    const inputs = await generateStudentStatusInputs();

    const outPath = path.join(__dirname, '..', 'testdata', 'student_status', 'input_valid.json');
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(inputs, null, 2) + '\n');
    console.log('Generated:', outPath);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
