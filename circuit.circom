pragma circom 2.0.0;
include "./poseidon.circom";
include "./utils.circom";

template Main() {
    // Poseidon hash width (how many field elements to hash)
    var w = 16;
    // The amount of last field element's high bits to use for
    // the plaintext. The rest of it will be used for the salt.
    var last_fe_bits = 125; 

    signal input plaintext_hash;
    signal input label_sum_hash;
    signal input plaintext[w];
    signal input delta[w-1][253];
    signal input delta_last[last_fe_bits];
    signal input sum_of_zero_labels;
    signal sums[w];

    component hash = Poseidon(w);
    for (var i = 0; i<w; i++) {
       hash.inputs[i] <== plaintext[i];
    }
    plaintext_hash === hash.out;

    // the last element of sum_of_deltas will contain the accumulated sum total
    signal sum_of_deltas[w+1];
    sum_of_deltas[0] <== 0; 
    
    // inner products of (deltas * plaintext bits) go here
    component ip[w-1];
    for (var i = 0; i<w-1; i++) {
       ip[i] = InnerProd(253);
       ip[i].plaintext <== plaintext[i];
       for (var j=0; j<253; j++) {
           ip[i].deltas[j] <== delta[i][j];
       }
       sum_of_deltas[i+1] <== sum_of_deltas[i] + ip[i].out;
    }
    // The last field element contains the salt, we make sure *not* to 
    // include the salt in the inner product. 
    component ip_last = InnerProd(last_fe_bits);
    ip_last.plaintext <== plaintext[w-1];
    for (var j=0; j<last_fe_bits; j++) {
        ip_last.deltas[j] <== delta_last[j];
    }

    sum_of_deltas[w] <==  sum_of_deltas[w-1] + ip_last.out;

    component ls_hash = Poseidon(1);
    ls_hash.inputs[0] <== sum_of_zero_labels + sum_of_deltas[w];
    label_sum_hash === ls_hash.out;
}
component main {public [plaintext_hash, label_sum_hash, delta, delta_last, sum_of_zero_labels]} = Main();