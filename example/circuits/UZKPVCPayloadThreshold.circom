pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/// Proves knowledge of VC commitment arrays and the value from included claim, which satisfies the predicate, reveals blinded digest
/// `Poseidon(Poseidon(header,payload), blinder_factor)`, and proves that
/// `Poseidon(fieldName, fieldValue)` equals one of `payload_commitments[i]`
/// (same per-field commitment as Dart `buildFieldCommitment`), with
/// `fieldValue > min_threshold` (252-bit integer order; inputs should be in-range).
template UZKPVCPayloadThreshold(NUM_HEADER, NUM_PAYLOAD) {
    assert(NUM_HEADER >= 1);
    assert(NUM_PAYLOAD >= 1);

    // First signals = public inputs (witness slots 1..3 for Groth16/snarkjs order).
    signal input fieldName;
    signal input min_threshold;
    signal input blinder_factor;

    signal output blinded_digest;

    signal input header_commitments[NUM_HEADER];
    signal input payload_commitments[NUM_PAYLOAD];
    signal input fieldValue;

    component documentDigest = Poseidon(NUM_HEADER + NUM_PAYLOAD);
    for (var i = 0; i < NUM_HEADER; i++) {
        documentDigest.inputs[i] <== header_commitments[i];
    }
    for (var i = 0; i < NUM_PAYLOAD; i++) {
        documentDigest.inputs[NUM_HEADER + i] <== payload_commitments[i];
    }

    component digestBlinder = Poseidon(2);
    digestBlinder.inputs[0] <== documentDigest.out;
    digestBlinder.inputs[1] <== blinder_factor;
    blinded_digest <== digestBlinder.out;

    component claimed = Poseidon(2);
    claimed.inputs[0] <== fieldName;
    claimed.inputs[1] <== fieldValue;

    component eq[NUM_PAYLOAD];
    for (var i = 0; i < NUM_PAYLOAD; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== claimed.out;
        eq[i].in[1] <== payload_commitments[i];
    }

    signal partial[NUM_PAYLOAD];
    partial[0] <== eq[0].out;
    for (var j = 1; j < NUM_PAYLOAD; j++) {
        partial[j] <== partial[j - 1] + eq[j].out;
    }

    component atLeastOne = IsZero();
    atLeastOne.in <== partial[NUM_PAYLOAD - 1];
    atLeastOne.out === 0;

    component valueGtMin = GreaterThan(252);
    valueGtMin.in[0] <== fieldValue;
    valueGtMin.in[1] <== min_threshold;
    valueGtMin.out === 1;
}

component main { public [fieldName, min_threshold, blinder_factor] } = UZKPVCPayloadThreshold(7, 5);
