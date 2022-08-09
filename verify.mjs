import * as snarkjs from "snarkjs";
// this workaround allows to require() from within ES6 modules 
// (which is not allowed by default in nodejs).
import { createRequire } from 'module'
const require = createRequire(import.meta.url)
const fs = require('fs');


async function main(retval){
    const pub_path = process.argv[2];
    const proof_path = process.argv[3];

    const vk = JSON.parse(fs.readFileSync("verification_key.json", "utf8"));
    const pub = JSON.parse(fs.readFileSync(pub_path, "utf8"));
    const proof = JSON.parse(fs.readFileSync(proof_path, "utf8"));

    const res = await snarkjs.groth16.verify(vk, pub, proof);
    if (res == true) {
        // exit code 0 means "the process exited successfully"
        retval = 0;
    }
    else {
        // any other exit code means "exited unsuccessfully" 
        retval = 99;
    }
    return retval;
}

main().then((retval) => {
    process.exit(retval);
});