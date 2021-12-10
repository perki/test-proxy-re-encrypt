const lib = require('./lib');

class API {
  constructor () {
    this.users = {};
    this.apiSignPrivateKey = lib.generateKeys().signPrivateKey; // we only need this for the server
  };
  createUser(userid, keys) {
    // here we also fully initailize the user
    this.users[userid] = {keys: keys, data: [], recipients: {}};
  };
  postUnencryptedData(userid, data) {
    const publicKey = this.users[userid].keys.publicKey;
    //Encrypt the data for user using server's signing key
    const encryptedValue = lib.encrypt(data, publicKey, this.apiSignPrivateKey);
    this.users[userid].data.push(encryptedValue);
  }; 
  postData(userid, encryptedValue) {
    this.users[userid].data.push(encryptedValue);
  }; 
  getData(userid, recipientid = 'personal') {
    const encryptedData = this.users[userid].data;
    
    // if personal send raw encrypted data
    if (recipientid === 'personal') return encryptedData;

    // else traansform data
    const res = [];
    for (const data of encryptedData) {
      res.push(lib.transform(data, this.users[userid].recipients[recipientid], this.apiSignPrivateKey));
    }
    return res;
  };
  postRecipient(userid, recipientid, userToTargetTransfromKey) {
    this.users[userid].recipients[recipientid] = userToTargetTransfromKey;
  };
  getPublicKeys(userid) {
    return this.users[userid].keys;
  }
}

module.exports = API;