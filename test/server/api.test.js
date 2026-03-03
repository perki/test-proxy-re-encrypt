const { assert } = require('chai');
const lib = require('../../src/lib');
const API = require('../../src/server/API');

for (const recryptType of lib.recryptTypes) {
  for (const envelopeType of lib.envelopeTypes) {
    const use = { envelope: envelopeType, recrypt: recryptType };

    describe(`API recrypt: ${recryptType}, envelope: ${envelopeType}`, function () {
      let api, userKeys, streamKeyId;

      const myData = {
        string: 'Hello from API test!',
        number: 42,
        nested: { ok: true }
      };

      before(async function () {
        api = new API();
        await api.init(use);

        userKeys = await lib.generateKeys('user1', use);
        streamKeyId = userKeys.public.id + ':' + recryptType + ':' + envelopeType;

        api.createUser('user1');
        api.createStream('user1', {
          id: 'streamA',
          clientData: {
            encryption: {
              publicKeySet: userKeys.public
            }
          }
        });
      });

      it('API encrypts unencrypted event, user decrypts', async function () {
        const event = {
          id: 'e1',
          streamIds: ['streamA'],
          type: 'note/txt',
          content: myData
        };

        await api.postUnencryptedEvent('user1', event, use);

        const events = await api.getEvents('user1');
        assert.lengthOf(events, 1);

        const encrypted = events[0];
        assert.equal(encrypted.type, 'encrypted');

        const keyId = Object.keys(encrypted.content)[0];
        const payload = encrypted.content[keyId];
        assert.isString(payload.encryptedPassword);
        assert.isString(payload.encryptedData);

        const decrypted = await lib.decryptWithKeys(payload, userKeys.privateKey);
        assert.deepEqual(decrypted, { type: 'note/txt', content: myData });
      });

      it('User posts client-encrypted event, retrieves and decrypts', async function () {
        const freshApi = new API();
        await freshApi.init(use);
        const keys = await lib.generateKeys('user2', use);

        freshApi.createUser('user2');
        freshApi.createStream('user2', {
          id: 'streamB',
          clientData: {
            encryption: {
              publicKeySet: keys.public
            }
          }
        });

        const clearData = { type: 'note/txt', content: 'Client encrypted data' };
        const encrypted = await lib.encryptWithKeys(clearData, keys, keys.public, use);

        const encryptedEvent = {
          id: 'e2',
          streamIds: ['streamB'],
          type: 'encrypted',
          content: { [encrypted.keyId]: encrypted }
        };

        freshApi.postEvent('user2', encryptedEvent);

        const events = await freshApi.getEvents('user2');
        assert.lengthOf(events, 1);

        const keyId = Object.keys(events[0].content)[0];
        const decrypted = await lib.decryptWithKeys(events[0].content[keyId], keys.privateKey);
        assert.deepEqual(decrypted, clearData);
      });

      it('User shares via proxy re-encryption, target decrypts', async function () {
        const freshApi = new API();
        await freshApi.init(use);

        const originKeys = await lib.generateKeys('origin', use);
        const targetKeys = await lib.generateKeys('target', use);

        freshApi.createUser('origin');
        freshApi.createStream('origin', {
          id: 'stream1',
          clientData: {
            encryption: {
              publicKeySet: originKeys.public
            }
          }
        });

        // Origin posts an encrypted event
        const clearData = { type: 'note/txt', content: 'Shared secret data' };
        const encrypted = await lib.encryptWithKeys(clearData, originKeys, originKeys.public, use);
        const encryptedEvent = {
          id: 'e3',
          streamIds: ['stream1'],
          type: 'encrypted',
          content: { [encrypted.keyId]: encrypted }
        };
        freshApi.postEvent('origin', encryptedEvent);

        // Origin creates a transform key for the target
        const transformKey = await lib.getTransformKey(originKeys, targetKeys.public);

        // Register the target with transform keys
        freshApi.postRecipient('origin', 'target', {
          transformKeys: { [encrypted.keyId]: transformKey }
        });

        // Target retrieves re-encrypted events
        const events = await freshApi.getEvents('origin', 'target');
        assert.lengthOf(events, 1);

        const reKeyId = Object.keys(events[0].content)[0];
        const reEncrypted = events[0].content[reKeyId];

        // Target decrypts with their own private key
        const decrypted = await lib.decryptWithKeys(reEncrypted, targetKeys.privateKey);
        assert.deepEqual(decrypted, clearData);
      });
    });
  }
}
