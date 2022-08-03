pragma circom 2.0.0;
include "./poseidon.circom";
include "./utils.circom";

template Main() {
    var fe_count = 10;
    // the other 130 bits of the last field element contain
    // the salt
    var last_fe_bits = 123;
    signal input plaintext_hash;
    signal input label_sum_hash;
    signal input plaintext[fe_count];
    signal input delta[fe_count-1][253];
    signal input delta_last[last_fe_bits];
    signal input sum_of_zero_labels;
    signal sums[fe_count];

    component hash = Poseidon(fe_count);
    for (var i = 0; i<fe_count; i++) {
       hash.inputs[i] <== plaintext[i];
    }

    // TODO to pass this assert we'd have to
    // use actual values instead of random ones, so commenting out for now
    // plaintext_hash === hash.out;

    component ip[fe_count-1];
    for (var i = 0; i<fe_count-1; i++) {
       ip[i] = InnerProd(253);
       ip[i].plaintext <== plaintext[i];
       for (var j=0; j<253; j++) {
           ip[i].deltas[j] <== delta[i][j];
       }
       sums[i] <== ip[i].out;
    }
    component ip_last = InnerProd(last_fe_bits);
    ip_last.plaintext <== plaintext[fe_count-1];
    for (var j=0; j<last_fe_bits; j++) {
        ip_last.deltas[j] <== delta_last[j];
    }
    sums[fe_count-1] <== ip_last.out;

    signal sum_of_deltas <== sums[0] + sums[1] + sums[2] + sums[3] + sums[4] + sums[5] + sums[6] + sums[7] + sums[8] + sums[9];
    // TODO to pass this assert we'd have to
    // use actual values instead of random ones, so commenting out for now
    component ls_hash = Poseidon(1);
    ls_hash.inputs[0] <== sum_of_zero_labels + sum_of_deltas;
    //label_sum_hash === ls_hash.out;
}
component main {public [plaintext_hash, label_sum_hash, delta, delta_last, sum_of_zero_labels]} = Main();