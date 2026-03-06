const ironcore = require('./ironcore');
const aldenmlecc = require('./aldenml-ecc');
const recryptjs = require('./recrypt-js');
const umbralpre = require('./umbral-pre');

const recrypts = {
  [ironcore.type]: ironcore,
  [aldenmlecc.type]: aldenmlecc,
  [recryptjs.type]: recryptjs,
  [umbralpre.type]: umbralpre,
}

module.exports = { get, list };

function list() {
  return Object.keys(recrypts);
}

function get(type) {
  const res = recrypts[type];
  if (res == null) throw new Error('Unsuported recrypt method :' + type);
  return res;
}