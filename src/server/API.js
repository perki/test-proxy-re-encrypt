/**
 * Mock API simulating a server that stores encrypted data
 * and performs proxy re-encryption transforms.
 */

const lib = require('../lib');

class API {
  constructor () {
    this.users = {};
    this.proxyKeys = null;
  }

  /**
   * Async initialization — must be called before using the API.
   * Generates the server's proxy signing keys.
   */
  async init (use = {}) {
    this.proxyKeys = await lib.generateKeys('api-proxy', use);
  }

  createUser (userId) {
    this.users[userId] = { streams: {}, events: [], recipients: {} };
  }

  createStream (userId, streamData) {
    this.users[userId].streams[streamData.id] = streamData;
  }

  /**
   * Encrypt an event server-side and store it.
   * The server encrypts using each stream's public key.
   */
  async postUnencryptedEvent (userId, event, use = {}) {
    const encryptedEvent = structuredClone(event);
    encryptedEvent.type = 'encrypted';
    encryptedEvent.content = {};

    const toEncrypt = { type: event.type, content: event.content };
    for (const streamId of event.streamIds) {
      const streamKeys = this.users[userId].streams[streamId].clientData.encryption;
      const publicKeySet = streamKeys.publicKeySet;
      const encrypted = await lib.encryptWithKeys(toEncrypt, this.proxyKeys, publicKeySet, use);
      encryptedEvent.content[encrypted.keyId] = encrypted;
    }

    this.postEvent(userId, encryptedEvent);
  }

  postEvent (userId, encryptedEvent) {
    this.users[userId].events.push(encryptedEvent);
  }

  /**
   * Get events, optionally re-encrypted for a target user.
   */
  async getEvents (fromUserId, toUserId) {
    const events = structuredClone(this.users[fromUserId].events);

    if (!toUserId) return events;

    const transformKeys = this.users[fromUserId].recipients[toUserId].transformKeys;
    for (const event of events) {
      for (const [keyId, content] of Object.entries(event.content)) {
        if (content.encryptedPassword && transformKeys[keyId]) {
          event.content[keyId] = await lib.recryptForKeys(
            content,
            transformKeys[keyId],
            this.proxyKeys
          );
        }
      }
    }
    return events;
  }

  /**
   * Get streams, optionally with passwords re-encrypted for a target user.
   */
  async getStreams (fromUserId, toUserId) {
    const streams = structuredClone(this.users[fromUserId].streams);
    if (!toUserId) return streams;

    const transformKeys = this.users[fromUserId].recipients[toUserId].transformKeys;
    for (const [, stream] of Object.entries(streams)) {
      const encryption = stream.clientData.encryption;
      if (encryption && encryption.encrypted) {
        const encrypted = encryption.encrypted;
        const transformKey = transformKeys[encrypted.keyId];
        if (transformKey && encrypted.encryptedPassword) {
          encryption.encrypted = await lib.recryptForKeys(
            encrypted,
            transformKey,
            this.proxyKeys
          );
        }
      }
    }
    return streams;
  }

  postRecipient (userId, recipientId, recipientData) {
    this.users[userId].recipients[recipientId] = recipientData;
  }
}

module.exports = API;
