pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output out;

    out <== a*b;
}

component main = Multiplier();

