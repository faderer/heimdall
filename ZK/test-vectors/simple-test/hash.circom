pragma circom 2.0.0;

include "../circuits/sha256/sha256_2.circom";

template Main() {
    signal input attr1;
    signal input attr2;
    signal output cred;

    component sha256_2 = Sha256_2();

    sha256_2.a <== attr1;
    sha256_2.b <== attr2;
    cred <== sha256_2.out;
}

component main = Main();