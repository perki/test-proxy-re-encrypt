/**
 *  Cryptography Functions
 */

const crypto = require('crypto');


module.exports = { decrypt, encrypt , type: 'aes-192-0'};

/**
 * Get encryption/decryption algorithm
 */
function getAlgorithm() {
   return 'aes192';
}

/**
 * Get encrypted string prefix
 */
function getEncryptedPrefix() {
   return 'aes-192-0::';
}

/**
 * Derive 256 bit encryption key from password, using salt and iterations -> 32 bytes
 * @param password
 * @param salt
 * @param iterations
 */
function deriveKeyFromPassword(password, salt, iterations) {
   return crypto.pbkdf2Sync(password, salt, iterations, 24, 'sha512');
}

/**
 * Encrypt AES 256 GCM
 * @param dataToEncrypt
 * @param password
 */
function encrypt(dataToEncrypt, password) {
   try {
      if (typeof dataToEncrypt === 'object') {
         dataToEncrypt = JSON.stringify(dataToEncrypt);
      } else {
         dataToEncrypt = String(dataToEncrypt);
      }

      const algorithm = getAlgorithm();

      // Generate random salt -> 64 bytes
      const salt = crypto.randomBytes(64);

      // Generate random initialization vector -> 16 bytes
      const iv = crypto.randomBytes(16);

      // Generate random count of iterations between 10.000 - 99.999 -> 5 bytes
      const iterations = Math.floor(Math.random() * (99999 - 10000 + 1)) + 10000;

      // Derive encryption key
      const encryptionKey = deriveKeyFromPassword(password, salt, Math.floor(iterations * 0.47 + 1337));

      // Create cipher
      // @ts-ignore: TS expects the wrong createCipher return type here
      const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);

      // Update the cipher with data to be encrypted and close cipher
      const encryptedData = Buffer.concat([cipher.update(dataToEncrypt, 'utf8'), cipher.final()]);

      // Join all data into single string, include requirements for decryption
      const output = Buffer.concat([salt, iv, Buffer.from(iterations.toString()), encryptedData]).toString('hex');

      return getEncryptedPrefix() + output;
   } catch (error) {
      console.error('Encryption failed!');
      console.error(error);
      return void 0;
   }
}

/**
 * Decrypt AES 256 GCM
 * @param cipherText
 * @param password
 */
function decrypt(cipherText, password) {
   try {
      const algorithm = getAlgorithm();

      const cipherTextParts = cipherText.split(getEncryptedPrefix());

      // If it's not encrypted by this, reject with undefined
      if (cipherTextParts.length !== 2) {
         console.error('Could not determine the beginning of the cipherText. Maybe not encrypted by this method.');
         return void 0;
      } else {
         cipherText = cipherTextParts[1];
      }

      const inputData = Buffer.from(cipherText, 'hex');

      // Split cipherText into partials
      const salt = inputData.subarray(0, 64);
      const iv = inputData.subarray(64, 80);
      const iterations = parseInt(inputData.subarray(80, 85).toString('utf-8'), 10);
      const encryptedData = inputData.subarray(85);

      // Derive key
      const decryptionKey = deriveKeyFromPassword(password, salt, Math.floor(iterations * 0.47 + 1337));

      // Create decipher
      const decipher = crypto.createDecipheriv(algorithm, decryptionKey, iv);

      // Decrypt data
      const decrypted = decipher.update(encryptedData, 'binary', 'utf-8') + decipher.final('utf-8');

      try {
         return JSON.parse(decrypted);
      } catch (error) {
         return decrypted;
      }
   } catch (error) {
      console.error('Decryption failed!');
      console.error(error);
      return void 0;
   }
}
