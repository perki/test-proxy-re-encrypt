const aes256gcm = require('./aes-256-gcm');

const envelopes = {
  [aes256gcm.type]: aes256gcm
}

module.exports = envelope;

function envelope(type) {
  const res = envelopes[type];
  if (res == null) throw new Error('Unsuported envelope method :' + type);
  return res;
}