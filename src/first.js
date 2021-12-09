const assert = require("assert");
const Recrypt = require("@ironcorelabs/recrypt-node-binding");

//Create a new Recrypt API instance
const Api256 = new Recrypt.Api256();

//Generate both a user key pair and a signing key pair
const pryvUserKeys = Api256.generateKeyPair();
const pryvUserSignKeys = Api256.generateEd25519KeyPair();

//Generate a plaintext to encrypt
const plaintext = new Buffer.alloc(384);
const msg = 'Helloé¢ 😜 World!';
const msgBuff = new Buffer.from(msg, 'utf8');
plaintext.fill(msgBuff, 0, msgBuff.length);

//Encrypt the data to the user public key
const encryptedValue = Api256.encrypt(plaintext, pryvUserKeys.publicKey, pryvUserSignKeys.privateKey);

//Generate a second public/private key pair as the target of the transform. This will allow the encrypted data to be
//transformed to this second key pair and allow it to be decrypted.
const targetKeys = Api256.generateKeyPair();
const targetKeysSignKeys = Api256.generateEd25519KeyPair();

//Generate a transform key from the user private key to the device public key
const userToTargetTransfromKey = Api256.generateTransformKey(pryvUserKeys.privateKey, targetKeys.publicKey, pryvUserSignKeys.privateKey);


//Transform the encrypted data (without decrypting it!) so that it can be decrypted with the second key pair
const encryptedValueForTarget = Api256.transform(encryptedValue, userToTargetTransfromKey, pryvUserSignKeys.privateKey);

//Decrypt the data using the second private key
const decryptedValue = Api256.decrypt(encryptedValueForTarget, targetKeys.privateKey);


console.log('*'+decryptedValue.toString('utf-8')+'*');

//
const targetToUserEncryptedValue = Api256.encrypt(plaintext, pryvUserKeys.publicKey, targetKeysSignKeys.privateKey);
const targetMsgDecryptedValue = Api256.decrypt(targetToUserEncryptedValue, pryvUserKeys.privateKey);

console.log('*'+targetMsgDecryptedValue.toString('utf-8')+'*');

assert.equal(0, Buffer.compare(plaintext, decryptedValue));