import * as circomlibjs from "circomlibjs";

async function main(){
    // field elements
    const fe = JSON.parse(process.argv[2]);
    const poseidonReference = await circomlibjs.buildPoseidonReference();
    const res = poseidonReference(fe);

    // convert to BE
    let buff = new Uint8Array(32);
    poseidonReference.F.toRprBE(buff, 0, res);
    const rv = bufToBn(buff);

    // print to stdout. This is how Rust gets the output
    console.log(bufToBn(buff).toString());
}

main().then(() => {
    process.exit(0);    
});

function bufToBn(buf) {
    var hex = [];
    const u8 = Uint8Array.from(buf);
  
    u8.forEach(function (i) {
      var h = i.toString(16);
      if (h.length % 2) { h = '0' + h; }
      hex.push(h);
    });
  
    return BigInt('0x' + hex.join(''));
  }

function bigToUint8Array(big) {
    let hex = big.toString(16)
    if (hex.length % 2) {
      hex = '0' + hex
    }
    const len = hex.length / 2
    const u8 = new Uint8Array(len)
    var i = 0
    var j = 0
    while (i < len) {
      u8[i] = parseInt(hex.slice(j, j + 2), 16)
      i += 1
      j += 2
    }
    return u8
  }