const ironcore = require('../src/recrypt')('ironcore-0');
ironcore.init(require('@ironcorelabs/recrypt-node-binding'));

const inspect = require('util').inspect;
function log() {
  const args = [...arguments].map((a) => inspect(a, false, 10, true));
  console.log(...args);
}

function stack (start = 0, length = 100) {
  const e = new Error();
  return e.stack.split('\n').filter(l => l.indexOf('node_modules') < 0).slice(start + 1, start + length + 1);
}

global.$$ = function logstack () {
  log(...arguments, stack(2, 4));
}