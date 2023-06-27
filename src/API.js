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
  getEvents(fromUserId, toUserId = 'personal') {
    const events = structuredClone(this.users[fromUserId].events);
    
    // if personal send raw encrypted data
    if (toUserId === 'personal') return events;

    // else traansform data
    const transformKeys = this.users[fromUserId].recipients[toUserId].transformKeys;
    for (const event of events) {
      const keyId = Object.keys(event.content)[0];
      const transformKey = transformKeys[keyId];
      if (event.content[keyId].encryptedPassword) {
        event.content[keyId].encryptedPassword = lib.transformPassword(event.content[keyId].encryptedPassword, transformKey, this.apiSignPrivateKey);
      } else {
        // do nothing recipient can use password encrypted in streamId
      }
    }
    return events;
  };
  getStreams(fromUserId, toUserId) {
    const streams = structuredClone(this.users[fromUserId].streams);
    const transformKeys = this.users[fromUserId].recipients[toUserId].transformKeys;
    for (const [streamId, stream] of Object.entries(streams)) {
      const encryption = stream.clientData.encryption;
      if (encryption != null && encryption['recrypt-aes-256-gcm-v1'] != null) {
        const encryptionItem = encryption['recrypt-aes-256-gcm-v1'];
        const keyId = fromUserId + ':' + streamId + ':0';
        const transformKey = transformKeys[keyId];
        encryptionItem.encryptedPassword = lib.transformPassword(encryptionItem.encryptedPassword, transformKey, this.apiSignPrivateKey);
      }
    }
    return streams;
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