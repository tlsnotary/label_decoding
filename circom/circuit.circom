pragma circom 2.0.0;
include "./poseidon.circom";
include "./utils.circom";

template Main() {
    // Poseidon hash rate (how many field elements are permuted at a time)
    var w = 16;
    // The amount of last field element's high bits (in big-endian) to use for
    // the plaintext. The rest of it will be used for the salt.
    var last_fe_bits = 125; 

    signal input plaintext_hash;
    signal input label_sum_hash;
    signal input plaintext[w];
    signal input salt;
    signal input delta[w-1][253];
    signal input delta_last[last_fe_bits];
    signal input sum_of_zero_labels;

    // acc.to the Poseidon paper, the 2nd element of the Poseidon state
    // is the hash digest
    component hash = PoseidonEx(w, 2);
    hash.initialState <== 0;
    for (var i = 0; i < w-1; i++) {
       hash.inputs[i] <== plaintext[i];
    }
    //add salt to the last element of plaintext shifting it left first
    hash.inputs[w-1] <== plaintext[w-1] * (1 << 128) + salt;
    log(1);
    plaintext_hash === hash.out[1];
    log(2);

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
       for (var j=0; j < useful_bits; j++) {
           if (i < w-1){
            ip[i].deltas[j] <== delta[i][j];
           }
           else {
            ip[i].deltas[j] <== delta_last[j];
           }
       }
       sum_of_deltas[i+1] <== sum_of_deltas[i] + ip[i].out;
    }
    
    // acc.to the Poseidon paper, the 2nd element of the Poseidon state
    // is the hash digest
    component ls_hash = PoseidonEx(1, 2);
    ls_hash.initialState <== 0;
    // shift the sum to the left and put the salt into the last 128 bits
    ls_hash.inputs[0] <== (sum_of_zero_labels + sum_of_deltas[w]) * (1 << 128) + salt;
    log(3);
    label_sum_hash === ls_hash.out[1];
    log(4);
}
component main {public [sum_of_zero_labels, plaintext_hash, label_sum_hash, delta, delta_last]} = Main();