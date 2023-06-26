/**
 * Mock an API
 */

const lib = require('./lib/recrypt');

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
      res.push(lib.transform(data, this.users[userid].recipients[recipientid].transformKey, this.apiSignPrivateKey));
    }
    return res;
  };
  postRecipient(userid, recipientid, recipientKeys) {
    this.users[userid].recipients[recipientid] = recipientKeys;
  };
  getPublicKeys(userid) {
    return this.users[userid].keys;
  }
  getRecipientsPublicKeys(userid) {
    const recipients = this.users[userid].recipients;
    const res = [];
    for (const recipientid in recipients) {
      res.push({recipientid: recipientid, publicKey: recipients[recipientid].publicKeys.publicKey});
    }
    return res;
  }

  rotateKeys(userid, newKeys) {
    this.users[userid].keys = newKeys.keys;
    // transform all data for this user
    const encryptedData = this.users[userid].data;
    const res = [];
    for (const data of encryptedData) {
      res.push(lib.transform(data, newKeys.transformKey, this.apiSignPrivateKey));
    }
    this.users[userid].data = res;

    // register new transforn keys for all recipients
    for (const newRecipientKey of newKeys.newRecipientTransformKeys) {
      this.users[userid].recipients[newRecipientKey.recipientid].transformKey = newRecipientKey.transformKey;
    }
  }
}

module.exports = API;