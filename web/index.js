//const Recrypt = require('@ironcorelabs/recrypt-wasm-binding');
import * as Recrypt from "@ironcorelabs/recrypt-wasm-binding";
const lib = require('../src/lib');
lib.init(Recrypt);

function clog() {
  document.write(...arguments);
  document.write('<br>');
}


require('../src/flow')(clog);
