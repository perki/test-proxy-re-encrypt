const lib = require('./lib/recrypt');
lib.init(require('@ironcorelabs/recrypt-node-binding'));

require('./flow')(console.log);
