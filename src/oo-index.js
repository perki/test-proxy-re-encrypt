const lib = require('./lib');
const API = require('./api');

const api = new API();


/**
 * We have two persons
 *  - "user" is an individual using and 'api' service
 *  - "target" is anothe individual who gets access to "user" data in r/w mode using the 'api' service
 * 
 *  The 'api' only holds encrypted data, 
 *      'user' only can decrypt the data.
 *      'target' can ddcrypt the data only when transformed by 'api' for him.
 * 
 *  The data is encrypted 'end' to 'end' with a central repository encrypted.
 * 
 *  An "attacker", should have either the private key of "user" or 
 *      the private key of "target" + the transform key hold on "api".
 */

class Access {
  constructor(userid, accessid) {
      this.userid = userid;
      this.accessid = accessid;
      this.keys = lib.generateKeys();
  }

  getPublicKeys() {
      return {publicKey: this.keys.publicKey, signPublicKey: this.keys.signPublicKey};
  }

  getData() {
    const encryptedData = api.getData(this.userid, this.accessid);
    const decryptedData = lib.decrypt(encryptedData, this.keys.privateKey);
    console.log(this.accessid + '>' + this.userid + '>', decryptedData);
    return decryptedData;
  }

  postData(data) {
    const userPublicKey = api.getPublicKeys(this.userid).publicKey;
    const encryptedData = lib.encrypt('Encrypted ' + this.userid + '/' + this.accessid + '> ' + data, userPublicKey, this.keys.signPrivateKey)
    api.postData(this.userid, encryptedData);
  }
}

class User {
  constructor(userid) {
      this.userid = userid;
      // create a personal access
      this.personalAccess = new Access(this.userid, 'personal');
      // create a new user on the api with his public keys
      api.createUser('user1', this.personalAccess.getPublicKeys());
  }

  getData() {
      return this.personalAccess.getData();
  }

  acceptAccessRequest(access) {
    const userToTargetTransfromKey = lib.getTransformKey(this.personalAccess.keys, access.getPublicKeys().publicKey);
    // 5.3 user register the target as an authorized recipient on the server
    api.postRecipient(this.userid, access.accessid, userToTargetTransfromKey);
  }

  postData(data) {
    this.personalAccess.postData(data);
  }

}


// 1- User creates his keys
const user = new User('user1');

// 3- Someone post Data to the server (any one can send unecrypted data to the server)
api.postUnencryptedData('user1', 'Unencrypted from someone');

// 4- User get his own data and decrypt it
user.getData();

// 5- A target ccreate a request to access user1 data 
const targetAccess = new Access('user1', 'target1');

// 5 target communicates his public key to the user who register it
user.acceptAccessRequest(targetAccess);

// 6- Target Get Data from the server
targetAccess.getData();

// 7- User sends encrypted data
user.postData('Data from myself');

// 8- Target sends encrypted data
targetAccess.postData('Hello user1');

// 9- User get his data
user.getData();

// 10- Target get user's data
targetAccess.getData();