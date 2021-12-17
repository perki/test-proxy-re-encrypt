const lib = require('./lib');
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

const ENCRYPTED_DATA_SIZE = 384;

function pack(obj) {
  const str = JSON.stringify(obj);
  const msgBuff = new Buffer.from(str, 'utf8');
  const res = [];
  console.log('msgBuff.length', msgBuff.length);
  for (i = 0; i < msgBuff.length; i += 384) {
    const buff384 = new Buffer.alloc(ENCRYPTED_DATA_SIZE, 0);
    msgBuff.copy(buff384, 0, i, i + 384);
    res.push(buff384);
  }
  return res;
}

const packedMessage = pack(objectWithData);

// 1- User creates his keys
const userKeys = lib.generateKeys();

// 2- A target send a request to access user data 
const targetKeys = lib.generateKeys();

// 3- user creates a transform key from his private key to the target public key
const userToTargetTransfromKey = lib.getTransformKey(userKeys, targetKeys.publicKey);

console.log(packedMessage);

const buffers = [];
for (const packedChunk of packedMessage) {
  const encryptedData = lib.encrypt384Buffer(packedChunk, userKeys.publicKey, userKeys.signPrivateKey);
  const decryptedData = lib.decrypt384Buffer(encryptedData, userKeys.privateKey);
  buffers.push(decryptedData);
}
console.log(Buffer.concat(buffers).toString());

