pragma circom 2.0.0;

include "../circuits/poseidon.circom";

template Commiter() {
    signal input attr0;
    signal input attr1;
    signal output cred;
    component hash = Poseidon(2);
    hash.inputs[0] <== attr0;
    hash.inputs[1] <== attr1;
    cred <== hash.out;
}

component main = Commiter();