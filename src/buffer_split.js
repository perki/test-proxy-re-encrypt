
const lib = require('./lib');
const buff384 = require('./lib/buff384')
lib.init(require('@ironcorelabs/recrypt-node-binding'));

const objectWithData = { 
  a: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  b: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
  c: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
  d: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
  e: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
  f: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
  g: 'jakskaskaskjsajasj😀kaskjkjasjkskasjkkjsakjkskjsakjkjsakjkjjksajkasjjkasajk',
}

function flow(data) {

  const packedMessage = buff384.pack(data);

  // 1- User creates his keys
  const userKeys = lib.generateKeys();

  // 2- A target send a request to access user data 
  const targetKeys = lib.generateKeys();

  // 3- user creates a transform key from his private key to the target public key
  const userToTargetTransfromKey = lib.getTransformKey(userKeys, targetKeys.publicKey);


  const encryptedPack = [];
  for (const packedChunk of packedMessage) {
    encryptedPack.push(lib.encrypt384Buffer(packedChunk, userKeys.publicKey, userKeys.signPrivateKey));
  }

  const decryptedPack = [];
  for (let i = 0; i < encryptedPack.length; i++) {
    const encryptedChunk = encryptedPack[i];
    const decryptedPackChunk = lib.decrypt384Buffer(encryptedChunk, userKeys.privateKey);
    decryptedPack.push(decryptedPackChunk);
  }

  //console.log(buff384.unpack(decryptedPack));
}


flow(objectWithData);

const stats = {}

let d = 'a';
for (let i = 0; i < 1000; i += 1) {
  d += 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const time = Date.now();
  flow(d);
  const diff = Date.now() - time;
  stats[d.length] = diff;
  console.log(d.length, diff, d.length / diff);
}
const fs = require('fs');
fs.writeFileSync('stats.json', JSON.stringify(stats, null, 2));
console.log(stats);
