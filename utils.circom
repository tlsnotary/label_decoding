
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

template InnerProd(){
    signal input plaintext;
    signal input deltas[254];
    signal output out;

    component n2b = Num2Bits(254);
    plaintext ==> n2b.in;

    signal sum[254];
    for (var i=0; i<254; i++) {
        sum[i] <== n2b.out[i] * deltas[i];
    }
    out <== (sum[0] + sum[1] + sum[2] + sum[3] + sum[4] + sum[5] + sum[6] + sum[7] + sum[8] + sum[9] + sum[10] + sum[11] + sum[12] + sum[13] + sum[14] + sum[15] + sum[16] + sum[17] + sum[18] + sum[19] + sum[20] + sum[21] + sum[22] + sum[23] + sum[24] + sum[25] + sum[26] + sum[27] + sum[28] + sum[29] + sum[30] + sum[31] + sum[32] + sum[33] + sum[34] + sum[35] + sum[36] + sum[37] + sum[38] + sum[39] + sum[40] + sum[41] + sum[42] + sum[43] + sum[44] + sum[45] + sum[46] + sum[47] + sum[48] + sum[49] + sum[50] + sum[51] + sum[52] + sum[53] + sum[54] + sum[55] + sum[56] + sum[57] + sum[58] + sum[59] + sum[60] + sum[61] + sum[62] + sum[63] + sum[64] + sum[65] + sum[66] + sum[67] + sum[68] + sum[69] + sum[70] + sum[71] + sum[72] + sum[73] + sum[74] + sum[75] + sum[76] + sum[77] + sum[78] + sum[79] + sum[80] + sum[81] + sum[82] + sum[83] + sum[84] + sum[85] + sum[86] + sum[87] + sum[88] + sum[89] + sum[90] + sum[91] + sum[92] + sum[93] + sum[94] + sum[95] + sum[96] + sum[97] + sum[98] + sum[99] + sum[100] + sum[101] + sum[102] + sum[103] + sum[104] + sum[105] + sum[106] + sum[107] + sum[108] + sum[109] + sum[110] + sum[111] + sum[112] + sum[113] + sum[114] + sum[115] + sum[116] + sum[117] + sum[118] + sum[119] + sum[120] + sum[121] + sum[122] + sum[123] + sum[124] + sum[125] + sum[126] + sum[127] + sum[128] + sum[129] + sum[130] + sum[131] + sum[132] + sum[133] + sum[134] + sum[135] + sum[136] + sum[137] + sum[138] + sum[139] + sum[140] + sum[141] + sum[142] + sum[143] + sum[144] + sum[145] + sum[146] + sum[147] + sum[148] + sum[149] + sum[150] + sum[151] + sum[152] + sum[153] + sum[154] + sum[155] + sum[156] + sum[157] + sum[158] + sum[159] + sum[160] + sum[161] + sum[162] + sum[163] + sum[164] + sum[165] + sum[166] + sum[167] + sum[168] + sum[169] + sum[170] + sum[171] + sum[172] + sum[173] + sum[174] + sum[175] + sum[176] + sum[177] + sum[178] + sum[179] + sum[180] + sum[181] + sum[182] + sum[183] + sum[184] + sum[185] + sum[186] + sum[187] + sum[188] + sum[189] + sum[190] + sum[191] + sum[192] + sum[193] + sum[194] + sum[195] + sum[196] + sum[197] + sum[198] + sum[199] + sum[200] + sum[201] + sum[202] + sum[203] + sum[204] + sum[205] + sum[206] + sum[207] + sum[208] + sum[209] + sum[210] + sum[211] + sum[212] + sum[213] + sum[214] + sum[215] + sum[216] + sum[217] + sum[218] + sum[219] + sum[220] + sum[221] + sum[222] + sum[223] + sum[224] + sum[225] + sum[226] + sum[227] + sum[228] + sum[229] + sum[230] + sum[231] + sum[232] + sum[233] + sum[234] + sum[235] + sum[236] + sum[237] + sum[238] + sum[239] + sum[240] + sum[241] + sum[242] + sum[243] + sum[244] + sum[245] + sum[246] + sum[247] + sum[248] + sum[249] + sum[250] + sum[251] + sum[252] + sum[253]);
}
