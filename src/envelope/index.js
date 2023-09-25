const aes256gcm = require('./aes-256-gcm');
const aes192 = require('./aes-192');

const envelopes = {
  [aes256gcm.type]: aes256gcm,
  [aes192.type]: aes192
}

module.exports = {
  get,
  list
}
  

function list() {
  return Object.keys(envelopes);
}

function get(type) {
  const res = envelopes[type];
  if (res == null) throw new Error('Unsuported envelope method :' + type);
  return res;
}