import sys
import random
import os

def padded_hex(s):
    h = hex(s)
    l = len(h)
    if l % 2 == 0:
        return h
    else:
        return '0x{0:0{1}x}'.format(s,l-1)

# This script will generate the circom circuit and inputs

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected 1 argument: amount of plaintext to process (in Field elements). Max 16')
        exit(1)
    count = int(sys.argv[1])
    if count > 16:
        print('Max 16 Field elements allowed. Got ', count)
        exit(1)

    input = '{\n'
    input += '"plaintext_hash": "'+str(random.randint(0, 2**254))+'",\n'
    input += '"label_sum_hash": "'+str(random.randint(0, 2**254))+'",\n'
    input += '"sum_of_zero_labels": "'+str(random.randint(0, 2**140))+'",\n'
    input += '"plaintext": [\n'
    for c in range(0, count):
        input += '    "'+str(random.randint(0, 2**253))+'"'
        if c < count-1:
            input += ',\n'
    input += "],\n"
    input += '"delta": [\n'
    for c in range(0, count):
        input += '  [\n'
        for x in range(0, 254):
            input += '    "'+str(random.randint(0, 2**253))+'"'
            if x < 253:
                input += ',\n'
        input += '  ]\n'
        if c < count-1:
            input += ',\n'
    input += ']\n'
    input += '}\n'
    
    with open('input.json', 'w') as f:
        f.write(input)

    main = 'pragma circom 2.0.0;\n'
    main += 'include "./poseidon.circom";\n'
    main += 'include "./utils.circom";\n'
    main += '\n'
    
    main += 'template Main() {\n'
    main += '    signal input plaintext_hash;\n'
    main += '    signal input label_sum_hash;\n'
    main += '    signal input plaintext['+str(count)+'];\n'
    main += '    signal input delta['+str(count)+'][253];\n'
    main += '    signal input sum_of_zero_labels;\n'
    main += '    signal sums['+str(count)+'];\n'
    main += '\n'

    main += '    component hash = Poseidon('+str(count)+');\n'
    main += '    for (var i = 0; i<'+str(count)+'; i++) {\n'
    main += '       hash.inputs[i] <== plaintext[i];\n'
    main += '    }\n'
    main += '\n'
    
    main += "    // TODO to pass this assert we'd have to\n"
    main += '    // use actual values instead of random ones, so commenting out for now\n'
    main += '    plaintext_hash === hash.out;\n'    
    main += '\n'

    # check that Prover's hash is correct. hashing 16 field elements at a time since 
    # idk how to chain hashes with circomlib. 
    # Using prev. digest as the first input to the next hash

    # if is_final is true then count includes the sum_of_labels
    # def hash(no, start, count, is_final=False):
    #     out = '    component hash_'+str(no)+' = Poseidon('+str(count)+');\n'
    #     if no > 0:
    #         #first element is prev. hash digest
    #         out += '    hash_'+str(no)+'.inputs[0] <== hash_'+str(no-1)+'.out;\n'
    #     else:
    #         if is_final and count == 1:
    #             out += '    hash_'+str(no)+'.inputs[0] <== sum_of_labels;\n'
    #         else:
    #             out += '    hash_'+str(no)+'.inputs[0] <== plaintext['+str(start)+'];\n'
    #     for x in range(1, count-1):
    #         out += '    hash_'+str(no)+'.inputs['+str(x)+'] <== plaintext['+str(start+x)+'];\n'
    #     if is_final:
    #         # sum of labels if the last input
    #         out += '    hash_'+str(no)+'.inputs['+str(count-1)+'] <== sum_of_labels;\n'
    #     else:
    #         out += '    hash_'+str(no)+'.inputs['+str(count-1)+'] <== plaintext['+str(start+count-1)+'];\n'
    #     out += '\n'
    #     return out

    # def hash_str():
    #     out = ''
    #     if count+1 <= 16:
    #         out += hash(0, 0, count+1, True)
    #         out += '    prover_hash <== hash_0.out;\n'
    #         return out
    #     else:
    #         out += hash(0, 0, 16, False)
    #     if count+1 <= 32:
    #         out += hash(1, 16, count+1-16, True)
    #         out += '    prover_hash <== hash_1.out;\n'
    #         return out
    #     else:
    #         out += hash(1, 16, 16, False)
    #     if count+1 <= 48:
    #         out += hash(2, 16, count+1-32, True)
    #         out += '    prover_hash <== hash_2.out;\n'
    #         return out
    #     else:
    #         out += hash(2, 16, 16, False)
    #     if count+1 <= 64:
    #         out += hash(3, 16, count+1-48, True)
    #         out += '    prover_hash <== hash_3.out;\n'
    #         return out
    #     else:
    #         out += hash(3, 16, 16, False)
    #     if count+1 <= 80:
    #         out += hash(4, 16, count+1-64, True)
    #         out += '    prover_hash <== hash_3.out;\n'
    #         return out
    #     else:
    #         out += hash(4, 16, 16, False)
         

    # main += '\n'
    # main += hash_str()
    # main += '\n'

    main += '    component ip['+str(count)+'];\n'
    main += '    for (var i = 0; i<'+str(count)+'; i++) {\n'
    main += '       ip[i] = InnerProd();\n'
    main += '       ip[i].plaintext <== plaintext[i];\n'
    main += '       for (var j=0; j<253; j++) {\n'
    main += '           ip[i].deltas[j] <== delta[i][j];\n'
    main += '       }\n'
    main += '       sums[i] <== ip[i].out;\n'
    main += '    }\n'
    main += '\n'    

    main += '    signal sum_of_deltas <== '
    for c in range(0, count):
        main += 'sums['+str(c)+']'
        if c < count-1:
            main += ' + '
        else:
            main += ';\n'

    main += "    // TODO to pass this assert we'd have to\n"
    main += '    // use actual values instead of random ones, so commenting out for now\n'
    main += '    component ls_hash = Poseidon(1);\n'
    main += '    ls_hash.inputs[0] <== sum_of_zero_labels + sum_of_deltas;\n'
    main += '    label_sum_hash === ls_hash.out;\n'
    main += '}\n'


    main += 'component main {public [plaintext_hash, label_sum_hash, delta, sum_of_zero_labels]} = Main();'
    with open('circuit.circom', 'w') as f:
        f.write(main)
    
