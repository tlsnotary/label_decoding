import * as snarkjs from "snarkjs";
import {createOverride} from "fastfile";
import bfj from "bfj";
import {  utils }   from "ffjavascript";
const {stringifyBigInts} = utils;
// this workaround allows to require() from within ES6 modules 
// (which is not allowed by default in nodejs).
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const fs = require('fs');


async function main(){
    const argv = process.argv;
    let entropy = argv[2];
    if (entropy.length != 500){
        process.exit(1);
    }

    const r1cs = fs.readFileSync("circuit.r1cs");
    const ptau = fs.readFileSync("powersOfTau28_hez_final_14.ptau");

    // snarkjs groth16 setup circuit.r1cs powersOfTau28_hez_final_14.ptau circuit_0000.zkey
    const zkey_0 = {type: "file", fileName: "circuit_0000.zkey"};
    await createOverride(zkey_0);
    console.log("groth16 setup...");
    await snarkjs.zKey.newZKey(r1cs, ptau, zkey_0);

    // snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey -e="<Notary's entropy>"
    const zkey_final = {type: "file", fileName: "circuit_final.zkey.notary"};
    await createOverride(zkey_final);
    console.log("zkey contribute...");
    await snarkjs.zKey.contribute(zkey_0, zkey_final, "", entropy);

    // snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
    console.log("zkey export...");
    const vKey = await snarkjs.zKey.exportVerificationKey(zkey_final);
    // copied from snarkjs/cli.js zkeyExportVKey()
    await bfj.write("verification_key.json", stringifyBigInts(vKey), { space: 1 });
}

main().then(() => {
    process.exit(0);
});