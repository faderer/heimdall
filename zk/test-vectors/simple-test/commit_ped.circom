pragma circom 2.0.0;

include "../circuits/pedersen.circom";

template Commiter() {
    signal input attr1;
    signal input attr2;
    signal input key1_0;
    signal input key1_1;
    signal input key2_0;
    signal input key2_1;
    signal output GI[2];
    signal output cred[2];
    component commitment = Pedersen(2);

    commitment.in[0] <== attr1;
    commitment.in[1] <== attr2;
    cred[0] <== commitment.out[0];
    cred[1] <== commitment.out[1];

    attr1 * (1 - attr1) === 0;
    attr2 * (1 - attr2) === 0;
    
    signal intermediate1_0;
    signal intermediate1_1;

    intermediate1_0 <== attr1 * key1_1;
    intermediate1_1 <== (1 - attr1) * key1_0;
    GI[0] <== intermediate1_0 + intermediate1_1;

    signal intermediate2_0;
    signal intermediate2_1;

    intermediate2_0 <== attr2 * key2_1;
    intermediate2_1 <== (1 - attr2) * key2_0;
    GI[1] <== intermediate2_0 + intermediate2_1;
}

component main = Commiter();
