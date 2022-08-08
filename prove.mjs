import * as snarkjs from "snarkjs";
import path from "path";
// this workaround allows to require() from within ES6 modules 
// (which is not allowed by default in nodejs).
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const fs = require('fs');


async function main(){
    const wtns = {type: "mem"};

    const input = fs.readFileSync("input.json");
    const wasm = fs.readFileSync(path.join("circuit_js", "circuit.wasm"));
    const zkey_final = fs.readFileSync("circuit_final.zkey");
    
    const in_json = JSON.parse(input);
    const res = await snarkjs.groth16.fullProve(in_json, wasm, zkey_final);
    const proof = res.proof;
    const publicSignals = res.publicSignals;
    // TODO writing public.json for now until verifier learns how to
    // construct it themselves
    fs.writeFileSync("public.json", JSON.stringify(publicSignals));
    // the Notary will generate the publicSignals themselves, we only need to 
    // send the proof
    fs.writeFileSync("proof.json", JSON.stringify(proof));
}

main().then(() => {
    process.exit(0);
});