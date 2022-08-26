import * as snarkjs from "snarkjs";
import path from "path";
// this workaround allows to require() from within ES6 modules 
// (which is not allowed by default in nodejs).
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const fs = require('fs');


async function main(){
    const input_path = process.argv[2];
    const proving_key_path = process.argv[3];
    const proof_path = process.argv[4];

    const input = fs.readFileSync(input_path);
    const wasm = fs.readFileSync(path.join("circuit_js", "circuit.wasm"));
    const zkey_final = fs.readFileSync(proving_key_path);
    
    const in_json = JSON.parse(input);
    const res = await snarkjs.groth16.fullProve(in_json, wasm, zkey_final);
   
    // the Notary will generate the publicSignals themselves, we only need to 
    // send the proof
    fs.writeFileSync(proof_path, JSON.stringify(res.proof));

    // Only for debugging 
    // fs.writeFileSync(proof_path + ".publicSignals", JSON.stringify(res.publicSignals));
}

main().then(() => {
    process.exit(0);
});