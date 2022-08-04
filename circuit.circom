pragma circom 2.0.0;
include "./poseidon.circom";
include "./utils.circom";

template Main() {
    // Poseidon hash width (how many field elements to hash)
    var w = 16;
    // The amount of last field element's high bits (in big-endian) to use for
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
    component ip[w];
    for (var i = 0; i<w; i++) {
       // The last field element contains the salt. We make sure *not* to 
       // include the salt in the inner product. 
       var useful_bits = i < w-1 ? 253 : last_fe_bits; 
       ip[i] = InnerProd(useful_bits);
       ip[i].plaintext <== plaintext[i];
       for (var j=0; j<useful_bits; j++) {
           if (i < w-1){
            ip[i].deltas[j] <== delta[i][j];
           }
           else {
            ip[i].deltas[j] <== delta_last[j];
           }
       }
       sum_of_deltas[i+1] <== sum_of_deltas[i] + ip[i].out;
    }
    
    component ls_hash = Poseidon(1);
    ls_hash.inputs[0] <== sum_of_zero_labels + sum_of_deltas[w];
    label_sum_hash === ls_hash.out;
}
component main {public [plaintext_hash, label_sum_hash, delta, delta_last, sum_of_zero_labels]} = Main();