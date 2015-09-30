'use strict';


var run = function() {
  // Replace '../bitcore' with 'bitcore' if you use this code elsewhere.
  var bitcore = require('../bitcore');
  var Parser = require('../util/BinaryParser');
  var Block = require('../lib/Block');
  var data = {
	 command: "parse" 
  };
 
  var testBlock = new Buffer([]);
  var parser = new Parser(testBlock);

  var block = new Block();
      block.parse(parser);

      data.block = block;
      data.version = block.version;
      data.prev_hash = block.prev_hash;
      data.merkle_root = block.merkle_root;
      data.timestamp = block.timestamp;
      data.bits = block.bits;
      data.nonce = block.nonce;

      data.txs = block.txs;

      data.size = testBlock.length;
    console.log(block);
};

module.exports.run = run;
if (require.main === module) {
  run();
}
