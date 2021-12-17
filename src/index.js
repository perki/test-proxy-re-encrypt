const lib = require('./lib');
lib.init(require('@ironcorelabs/recrypt-node-binding'));

require('./flow')(console.log);
