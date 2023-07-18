const ironcore = require('./ironcore');


const recrypts = {
  [ironcore.type]: ironcore,
}

module.exports = recrypt;

function recrypt(type) {
  const res = recrypts[type];
  if (res == null) throw new Error('Unsuported recrypt method :' + type);
  return res;
}