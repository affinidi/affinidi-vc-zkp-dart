pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// Proves knowledge of VC commitment arrays and the value from included claim, which satisfies the predicate, reveals blinded digest
/// `Poseidon(Poseidon(header,payload), blinder_factor)`, and proves that
/// indexed typed commitment for claimed payload equals one of
/// `payload_commitments[i]`:
/// commitment = Poseidon([index, fieldNameRaw, TYPE_INT, fieldValue])
/// (same per-field commitment as Dart `buildFieldCommitment`), with
/// `fieldValue > min_threshold` in 252-bit unsigned integer semantics.
/// In-range is enforced by constraints via Num2Bits(252) for both values.
template UZKPVCPayloadThreshold(NUM_HEADER, NUM_PAYLOAD) {
    var TYPE_INT = 2;
    assert(NUM_HEADER >= 1);
    assert(NUM_PAYLOAD >= 1);

    // First signals = public inputs (witness slots 1..3 for Groth16/snarkjs order).
    signal input fieldName;
    signal input min_threshold;
    signal input blinder_factor;

    signal output blinded_digest;

    signal input header_commitments[NUM_HEADER];
    signal input payload_commitments[NUM_PAYLOAD];
    signal input payloadIndex;
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

    component claimed = Poseidon(4);
    claimed.inputs[0] <== payloadIndex;
    claimed.inputs[1] <== fieldName;
    claimed.inputs[2] <== TYPE_INT;
    claimed.inputs[3] <== fieldValue;

    // Dynamic index lookup emulation:
    // - hash claimed commitment once
    // - select payload_commitments[payloadIndex] via one-hot selector
    component indexEq[NUM_PAYLOAD];
    signal selectedCommitmentAcc[NUM_PAYLOAD];
    signal selectorCountAcc[NUM_PAYLOAD];
    for (var i = 0; i < NUM_PAYLOAD; i++) {
        indexEq[i] = IsEqual();
        indexEq[i].in[0] <== payloadIndex;
        indexEq[i].in[1] <== i;
        if (i == 0) {
            selectedCommitmentAcc[i] <== indexEq[i].out * payload_commitments[i];
            selectorCountAcc[i] <== indexEq[i].out;
        } else {
            selectedCommitmentAcc[i] <== selectedCommitmentAcc[i - 1] + indexEq[i].out * payload_commitments[i];
            selectorCountAcc[i] <== selectorCountAcc[i - 1] + indexEq[i].out;
        }
    }
    // Enforces payloadIndex to be in [0, NUM_PAYLOAD - 1] and unique.
    selectorCountAcc[NUM_PAYLOAD - 1] === 1;
    claimed.out === selectedCommitmentAcc[NUM_PAYLOAD - 1];

    component valueGtMin = GreaterThan(252);
    component fieldValueRange = Num2Bits(252);
    fieldValueRange.in <== fieldValue;
    component minThresholdRange = Num2Bits(252);
    minThresholdRange.in <== min_threshold;
    valueGtMin.in[0] <== fieldValue;
    valueGtMin.in[1] <== min_threshold;
    valueGtMin.out === 1;
}

component main { public [fieldName, min_threshold, blinder_factor] } = UZKPVCPayloadThreshold(7, 5);
