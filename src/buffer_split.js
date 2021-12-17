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

const TYPES = {
    NUMBER: 0,
    STRING: 1,
    OBJECT: 2,
    JSON: 3,
    BUFFER: 4
}

function pack(obj) {
  const type = 3;
  const str = JSON.stringify(obj);
  const msgBuff = new Buffer.from(str, 'utf8');
  const msgTotalLength = 2 + msgBuff.length;
  const lastLineLength = msgTotalLength % ENCRYPTED_DATA_SIZE;

  const res = [];
  console.log('msgBuff.length', msgBuff.length);
  let i = 0;
  while (i < msgTotalLength) {
    const buff384 = new Buffer.alloc(ENCRYPTED_DATA_SIZE, 98);
    if (i === 0) { // first line
      buff384[0] = type;
      buff384[1] = lastLineLength;
      msgBuff.copy(buff384, 2, 0, ENCRYPTED_DATA_SIZE - 2);
      i += ENCRYPTED_DATA_SIZE - 2;
    } else {
      msgBuff.copy(buff384, 0, i + 2, ENCRYPTED_DATA_SIZE);
      i += ENCRYPTED_DATA_SIZE;
    }
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
const type = decryptedPack[0][0];
const lastLineLength = decryptedPack[0][1];
decryptedPack[0] = decryptedPack[0].slice(2); // remove the 2 first bytes of first line
decryptedPack[decryptedPack.length-1] = decryptedPack[decryptedPack.length-1].slice(0, lastLineLength ); // remove the last bytes of last line

console.log(type, lastLineLength, Buffer.concat(decryptedPack).toString());
if (type === TYPES.JSON) {
  const result = JSON.parse(Buffer.concat(decryptedPack).toString('utf8'));
  console.log(result);
}





