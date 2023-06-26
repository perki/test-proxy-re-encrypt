/**
 * Mock an API
 */

const lib = require('./lib/recrypt');

class API {
  constructor () {
    this.users = {};
    // we need this for the server to sign eventual transformations
    this.apiSignPrivateKey = lib.generateKeys().signPrivateKey; 
  };
  createUser(userId) {
    // here we also fully initailize the user
    this.users[userId] = {streams: {}, events: [], recipients: {}};
  };
  createStream(userId, streamData) {
    this.users[userId].streams[streamData.id] = streamData;
  };
  postUnencryptedEvent(userId, event) {
    const encryptedEvent = structuredClone(event);
    encryptedEvent.type = 'encrypted/recrypt-aes-256-gcm-v1';
    encryptedEvent.content = {};

    const toEncrypt = { type: event.type, content: event.content };
    for (const streamId of event.streamIds) { // Encrypt the data using streams signing key
      const keys = this.users[userId].streams[streamId].clientData.encryption['recrypt-aes-256-gcm-v1'];
      const encryptedValue = lib.encrypt(toEncrypt, keys.publicKey, this.apiSignPrivateKey);
      encryptedEvent.content[keys.id] = encryptedValue;
    }
    
    this.postEvent(userId, encryptedEvent);
  }; 
  postEvent(userId, encryptedEvent) {
    this.users[userId].events.push(encryptedEvent);
  }; 
  getData(userId, recipientid = 'personal') {
    const encryptedData = this.users[userId].events;
    
    // if personal send raw encrypted data
    if (recipientid === 'personal') return encryptedData;

    // else traansform data
    const res = [];
    for (const data of encryptedData) {
      res.push(lib.transform(data, this.users[userId].recipients[recipientid].transformKey, this.apiSignPrivateKey));
    }
    return res;
  };
  postRecipient(userId, recipientid, recipientKeys) {
    this.users[userId].recipients[recipientid] = recipientKeys;
  };
  getPublicKeys(userId) {
    return this.users[userId].keys;
  }
  getRecipientsPublicKeys(userId) {
    const recipients = this.users[userId].recipients;
    const res = [];
    for (const recipientid in recipients) {
      res.push({recipientid: recipientid, publicKey: recipients[recipientid].publicKeys.publicKey});
    }
    return res;
  }

  rotateKeys(userId, newKeys) {
    this.users[userId].keys = newKeys.keys;
    // transform all data for this user
    const encryptedData = this.users[userId].data;
    const res = [];
    for (const data of encryptedData) {
      res.push(lib.transform(data, newKeys.transformKey, this.apiSignPrivateKey));
    }
    this.users[userId].data = res;

    // register new transforn keys for all recipients
    for (const newRecipientKey of newKeys.newRecipientTransformKeys) {
      this.users[userId].recipients[newRecipientKey.recipientid].transformKey = newRecipientKey.transformKey;
    }
  }
}

module.exports = API;