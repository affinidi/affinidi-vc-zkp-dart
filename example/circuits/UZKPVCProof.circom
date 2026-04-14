pragma circom 2.1.6;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";

/// Untraceable ZK VC proof: document digest = Poseidon([...header_commitments, ...payload_commitments])
/// (`NUM_HEADER + NUM_PAYLOAD` inputs), then EdDSAPoseidon over that digest.
/// Holder is bound to `header_commitments[1]` and `[2]` (needs `NUM_HEADER >= 3`)
/// with indexed typed commitments:
/// commitment = Poseidon([index, fieldNameRaw, TYPE_INT, holderCoord])
/// for keys `holderAx` / `holderAy` in
/// alphabetical header order (Dart VC demo uses 7 + 5). For Dart/Rust FFI
/// Public `blinder_factor` and `blinded_digest` link to other circuits:
/// `blinded_digest = Poseidon(document_digest, blinder_factor)`.
template UZKPVCProof(NUM_HEADER, NUM_PAYLOAD) {
    var TYPE_INT = 2;

    // Header JSON keys as UTF-8 string -> field element (hex BE, len <= 31);
    // must match Dart `stringToFieldElement` for those names.
    // Plain text: "holderAx"
    var HOLDER_AX_FIELD_NAME_RAW = 7525352680813904248;
    // Plain text: "holderAy"
    var HOLDER_AY_FIELD_NAME_RAW = 7525352680813904249;

    signal input header_commitments[NUM_HEADER];
    signal input payload_commitments[NUM_PAYLOAD];
    signal input issuerAx;
    signal input issuerAy;
    signal input documentR8x;
    signal input documentR8y;
    signal input documentS;
    signal input holderAx;
    signal input holderAy;
    signal input challengeDigest;
    signal input challengeR8x;
    signal input challengeR8y;
    signal input challengeS;

    signal input blinder_factor;
    signal output blinded_digest;

    component documentDigest = Poseidon(NUM_HEADER + NUM_PAYLOAD);
    for (var i = 0; i < NUM_HEADER; i++) {
        documentDigest.inputs[i] <== header_commitments[i];
    }
    for (var i = 0; i < NUM_PAYLOAD; i++) {
        documentDigest.inputs[NUM_HEADER + i] <== payload_commitments[i];
    }

    component documentEdDSAVerifier = EdDSAPoseidonVerifier();
    documentEdDSAVerifier.enabled <== 1;
    documentEdDSAVerifier.Ax <== issuerAx;
    documentEdDSAVerifier.Ay <== issuerAy;
    documentEdDSAVerifier.R8x <== documentR8x;
    documentEdDSAVerifier.R8y <== documentR8y;
    documentEdDSAVerifier.S <== documentS;
    documentEdDSAVerifier.M <== documentDigest.out;

    component digestBlinder = Poseidon(2);
    digestBlinder.inputs[0] <== documentDigest.out;
    digestBlinder.inputs[1] <== blinder_factor;
    blinded_digest <== digestBlinder.out;

    component bindHolderAx = Poseidon(4);
    bindHolderAx.inputs[0] <== 1;
    bindHolderAx.inputs[1] <== HOLDER_AX_FIELD_NAME_RAW;
    bindHolderAx.inputs[2] <== TYPE_INT;
    bindHolderAx.inputs[3] <== holderAx;
    bindHolderAx.out === header_commitments[1];

    component bindHolderAy = Poseidon(4);
    bindHolderAy.inputs[0] <== 2;
    bindHolderAy.inputs[1] <== HOLDER_AY_FIELD_NAME_RAW;
    bindHolderAy.inputs[2] <== TYPE_INT;
    bindHolderAy.inputs[3] <== holderAy;
    bindHolderAy.out === header_commitments[2];

    component challengeEdDSAVerifier = EdDSAPoseidonVerifier();
    challengeEdDSAVerifier.enabled <== 1;
    challengeEdDSAVerifier.Ax <== holderAx;
    challengeEdDSAVerifier.Ay <== holderAy;
    challengeEdDSAVerifier.R8x <== challengeR8x;
    challengeEdDSAVerifier.R8y <== challengeR8y;
    challengeEdDSAVerifier.S <== challengeS;
    challengeEdDSAVerifier.M <== challengeDigest;
}

component main { public [issuerAx, issuerAy, challengeDigest, blinder_factor] } = UZKPVCProof(7, 5);
