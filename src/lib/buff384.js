/**
 * We only found how to use recrypt with buffer of 384 bytes.
 * These function are used to prepare a data object to be encrypted and decrypted.
 * 1- Convert the data object in String (JSON.stringify))
 * 2- Convert the String in Buffer (utf8encoder.encode) (we use Uint8Array for brower support)
 * 3- Split the Buffer in 384 bytes chunks
 *  
 * Note: the 3 firsts bytes of the first line are used to store the type of data (JSON) and the length of the last line.
 */

const utf8decoder = new TextDecoder(); // default 'utf-8' or 'utf8'
const utf8encoder = new TextEncoder(); // default 'utf-8' or 'utf8'

/**
 * Will be set as the first character of the first line.
 */
const TYPES = {
  JSON: 0, // handles, number, strings, booleans, null, objects, arrays
  BUFFER: 1
}

const ENCRYPTED_DATA_SIZE = 384;
const HEADER_LENGTH = 3;

/**
 * Copy data from a buffer to another buffer.
 * @param {Uint8Array|Buffer} source 
 * @param {Uint8Array} target 
 * @param {integer} targetStart 
 * @param {integer} sourceStart 
 * @param {integer} sourceEnd 
 */
function copyBuffInto(source, target, targetStart, sourceStart, sourceEnd) {
  for (let i = 0; (sourceStart + i) < sourceEnd; i++) {
    target[targetStart + i] = source[sourceStart + i];
  }
}

function pack(data) {
  let type = TYPES.JSON;
  let msg = null;
  msg = JSON.stringify(data);
  const msgBuff = utf8encoder.encode(msg);
  const msgTotalLength = HEADER_LENGTH + msgBuff.length;
  const lastLineLength = msgTotalLength % ENCRYPTED_DATA_SIZE;

  const res = [];
  console.log('msgBuff.length', msgBuff.length);
  let i = 0;
  while (i < msgBuff.length) {
    const buff384 = new Uint8Array(ENCRYPTED_DATA_SIZE);
    if (i === 0) { // first line
      buff384[0] = type;
      buff384[1] = lastLineLength > 254 ? 255 : lastLineLength;
      buff384[2] = lastLineLength > 254 ? lastLineLength - 255: 0;
      console.log('******', buff384);
      copyBuffInto(msgBuff, buff384, HEADER_LENGTH, 0, ENCRYPTED_DATA_SIZE - HEADER_LENGTH);
      i += ENCRYPTED_DATA_SIZE - HEADER_LENGTH;
    } else {
      copyBuffInto(msgBuff, buff384, 0, i, i + ENCRYPTED_DATA_SIZE);
      i += ENCRYPTED_DATA_SIZE;
    }
    res.push(buff384);
  }
  return res;
}


function unpack(decryptedPack) {
  const type = decryptedPack[0][0];
  const lastLineLength = decryptedPack[0][1] + decryptedPack[0][2];
  console.log(decryptedPack.map(x => x.toString('utf8')));
  if (lastLineLength > 0)
    decryptedPack[decryptedPack.length-1] = decryptedPack[decryptedPack.length-1].slice(0, lastLineLength ); // remove the last bytes of last line
  decryptedPack[0] = decryptedPack[0].slice(HEADER_LENGTH); // remove the 3 firsts bytes of first line
  console.log(type, lastLineLength, Buffer.concat(decryptedPack).toString());
  if (type === TYPES.JSON) {
    const result = JSON.parse(Buffer.concat(decryptedPack).toString('utf8'));
    return result;
  }
  return Buffer.concat(decryptedPack);
}



module.exports = {
  pack,
  unpack
}