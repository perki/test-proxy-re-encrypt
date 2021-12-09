const lib = require('./lib');

class API {
  constructor () {
    this.users = {};
    this.apiSignPrivateKey = lib.generateKeys().signPrivateKey; // we only need this for the server
  };
  postPublicKeys(userid, keys) {
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
  getData(userid) {
    return this.users[userid].data;
  };
  getDataFor(userid, recipientid) {
    const res = [];
    for (const data of this.users[userid].data) {
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