const ironcore = require('./ironcore');
const aldenmlecc = require('./ecc');

const recrypts = {
  [ironcore.type]: ironcore,
  [aldenmlecc.type]: aldenmlecc,
}

module.exports = recrypt;



function recrypt(type) {
  const res = recrypts[type];
  if (res == null) throw new Error('Unsuported recrypt method :' + type);
  return res;
}