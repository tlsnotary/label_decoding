pragma circom 2.0.0;

// copied from circomlib/circuits/bitify.circom
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

template InnerProd(count){
    signal input plaintext;
    signal input deltas[count];
    signal output out;

    component n2b = Num2Bits(253);
    plaintext ==> n2b.in;

    signal sum[count];
    for (var i=0; i<count; i++) {
        // Num2Bits returns bits in "least bit first" order
        // but deltas are in the opposite bit order.
        // So, we reverse the bits.
        sum[i] <== n2b.out[count-1-i] * deltas[i];
    }

    var total = 0;
    for (var i=0; i<count; i++) {
        total += sum[i];
    }

    out <== total;
}

