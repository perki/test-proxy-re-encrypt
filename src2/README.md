
# Client API

generateRecryptKeys(userId, keyId, type)

```
{
  privateKey: '...',
  signPrivateKey: '...',
  public: {
    type: 'ironcore-0',
    id: '{userId}:{keyId}',
    publicKey: '....',
    signPublicKey: '....',
    encryptedPassword: '.....',
  }
}
```




# Proxy Re-Crypt expected API

Encrypted Stream Model
```
{
  id: 'streamA', 
  clientData: { 
    encryption : {
      type: 'ironcore-0:gcm-0',
      publicKey: keyForStreamA.public,
      id: ''
    } 
  }
}
```



Encrypted Event Model

```
{
  type: 'encrypted/recrypt-aes-256-gcm-v1'
  content: {
    'keyId': { // matching streamId Key
      encyptedData: '....'
    }
  }
}
```

