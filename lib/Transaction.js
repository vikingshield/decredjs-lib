var config = require('../config');
var log = require('../util/log');
var Address = require('./Address');
var Script = require('./Script');
var _ = require('lodash');
var ScriptInterpreter = require('./ScriptInterpreter');
var util = require('../util');
var crypto = require('crypto');
var bignum = require('bignum');
var Put = require('bufferput');
var Parser = require('../util/BinaryParser');
var buffertools = require('buffertools');
var error = require('../util/error');
var WalletKey = require('./WalletKey');
var PrivateKey = require('./PrivateKey');
var preconditions = require('preconditions').singleton();
var BufferReader = require('./encoding/bufferreader');
var BufferWriter = require('./encoding/bufferwriter');
var blake256 = util.blake256;
var BN = require('./crypto/bn');

var COINBASE_OP = Buffer.concat([util.NULL_HASH, new Buffer('FFFFFFFF', 'hex')]);
var STAKEBASE_OP = Buffer.concat([util.NULL_HASH, new Buffer('00000000', 'hex')]);
var FEE_PER_1000B_SAT = parseInt(0.0001 * util.COIN);

var CURRENT_VERSION = 1;
var CURRENT_PREFIX_VER = 65537;
var CURRENT_WITNESS_VER = 131073;

Transaction.COINBASE_OP = COINBASE_OP;
function areBuffersEqual(bufA, bufB) {
  var len = bufA.length;
  if (len !== bufB.length) {
    return false;
  }
  for (var i = 0; i < len; i++) {
    if (bufA.readUInt8(i) !== bufB.readUInt8(i)) {
      return false;
    }
  }
  return true;
}

function TransactionIn(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  if (data.o) {
    this.o = data.o;
  } else {
    if (data.oTxHash && typeof data.oIndex !== 'undefined' && data.oIndex >= 0) {
      var hash = new Buffer(data.oTxHash, 'hex');
      hash = buffertools.reverse(hash);
      var voutBuf = new Buffer(4);
      voutBuf.writeUInt32LE(data.oIndex, 0);
      this.o = Buffer.concat([hash, voutBuf]);
    }
  }
  this.s = Buffer.isBuffer(data.s) ? data.s :
    Buffer.isBuffer(data.script) ? data.script : util.EMPTY_BUFFER;
  this.q = data.q ? data.q : data.sequence;
}

function TransactionInPrefix(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  if (data.o) {
    this.o = data.o;
  } else {
    if (data.oTxHash && typeof data.oIndex !== 'undefined' && data.oIndex >= 0) {
      var hash = new Buffer(data.oTxHash, 'hex');
      hash = buffertools.reverse(hash);
      var voutBuf = new Buffer(4);
      voutBuf.writeUInt32LE(data.oIndex, 0);
      this.o = Buffer.concat([hash, voutBuf]);
    }
  }
  this.s = util.EMPTY_BUFFER;
  this.q = data.q ? data.q : data.sequence;
}

function TransactionInWitness(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.s = Buffer.isBuffer(data.s) ? data.s :
    Buffer.isBuffer(data.script) ? data.script : util.EMPTY_BUFFER;
}

TransactionIn.MAX_SEQUENCE = 0xffffffff;

TransactionIn.prototype.getScript = function getScript() {
  return new Script(this.s);
};

TransactionIn.prototype.isCoinBase = function isCoinBase() {
  if (!this.o) return false;

  //The new Buffer is for Firefox compatibility
  return buffertools.compare(new Buffer(this.o), COINBASE_OP) === 0;
};

TransactionIn.prototype.isStakeBase = function isStakeBase() {
  if (!this.o) return false;

  //The new Buffer is for Firefox compatibility
  return buffertools.compare(new Buffer(this.o), COINBASE_OP) === 0;
};

TransactionIn.prototype.serialize = function serialize() {
  var slen = util.varIntBuf(this.s.length);
  var qbuf = new Buffer(4);
  qbuf.writeUInt32LE(this.q, 0);

  var ret = Buffer.concat([this.o, slen, this.s, qbuf]);
  return ret;
};

TransactionIn.prototype.serializePrefix = function serializePrefix() {
  var qbuf = new Buffer(4);
  qbuf.writeUInt32LE(this.q, 0);
  var ret = Buffer.concat([this.o, qbuf]);
  return ret;
};

TransactionIn.prototype.serializeWitness = function serializeWitness() {
// Write null values for the fraud proofs so the miners can fill them
// out.
// AmountIn = 0xFFFFFFFFFFFFFFFF
// BlockHeight = 0x00000000
// BlockIndex = 0xFFFFFFFF
  var allZs = new Buffer(4);
  allZs.writeUInt32LE(0x00000000, 0);
  allFs = new Buffer(4);
  allFs.writeUInt32LE(0xFFFFFFFF, 0);
             
  var slen = util.varIntBuf(this.s.length);
  var ret = Buffer.concat([allFs, allFs, allZs, allFs, slen, this.s]);
  return ret;
};

TransactionIn.prototype.getOutpointHash = function getOutpointHash() {
  if ("undefined" !== typeof this.o.outHashCache) {
    return this.o.outHashCache;
  }
  return this.o.outHashCache = this.o.slice(0, 32);
};

TransactionIn.prototype.getOutpointIndex = function getOutpointIndex() {
  return (this.o[32]) +
    (this.o[33] << 8) +
    (this.o[34] << 16) +
    (this.o[35] << 24);
};

TransactionIn.prototype.setOutpointIndex = function setOutpointIndex(n) {
  this.o[32] = n & 0xff;
  this.o[33] = n >> 8 & 0xff;
  this.o[34] = n >> 16 & 0xff;
  this.o[35] = n >> 24 & 0xff;
};

TransactionIn.prototype.getOutpointTree = function getOutpointTree() {
  return (this.o[36]);
}

TransactionIn.prototype.setOutpointTree = function setOutpointTree(n) {
  this.o[36] = (n & 0xff) << 24 >> 24;
}

function TransactionOut(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.v = data.v ? data.v : data.value;
  this.s = data.s ? data.s : data.script;
};

TransactionOut.prototype.getValue = function getValue() {
  return new Parser(this.v).word64lu();
};

TransactionOut.prototype.getScript = function getScript() {
  return new Script(this.s);
};

TransactionOut.prototype.serialize = function serialize() {
// Script version.
  var vbuf = new Buffer(2);
  vbuf.writeUInt16LE(0x0000, 0);  
// Script length.
  var slen = util.varIntBuf(this.s.length);
  return Buffer.concat([this.v, vbuf, slen, this.s]);
};

function Transaction(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.hash = data.hash || null;
  this.version = data.version;
  this.ins = Array.isArray(data.insP) ? data.ins.map(function(data) {
    var txin = new TransactionInPrefix();
    txin.s = data.s;
    txin.q = data.q;
    txin.o = data.o;
    return txin;
  }) : [];
  this.outs = Array.isArray(data.outs) ? data.outs.map(function(data) {
    var txout = new TransactionOut();
    txout.v = data.v;
    txout.s = data.s;
    return txout;
  }) : [];
  this.lock_time = data.lock_time;
  this.expiry = data.expiry;
  if (data.buffer) this._buffer = data.buffer;
};
Transaction.In = TransactionIn;
Transaction.Out = TransactionOut;

Transaction.prototype.isCoinBase = function() {
  return this.ins.length == 1 && this.ins[0].isCoinBase();
};

Transaction.prototype.isStakeBase = function() {
  return this.ins.length == 1 && this.ins[0].isStakeBase();
};

Transaction.prototype.isStandard = function isStandard() {
  var i;
  for (i = 0; i < this.ins.length; i++) {
    if (this.ins[i].getScript().getInType() == "Strange") {
      return false;
    }
  }
  for (i = 0; i < this.outs.length; i++) {
    if (this.outs[i].getScript().getOutType() == "Strange") {
      return false;
    }
  }
  return true;
};

Transaction.prototype.serialize = function serialize() {
  var bufs = [];

  // Version
  var buf = new Buffer(4);
  buf.writeUInt32LE(this.version, 0);
  bufs.push(buf);

  // TxIns (Prefix)
  bufs.push(util.varIntBuf(this.ins.length));
  this.ins.forEach(function(txin) {
    bufs.push(txin.serializePrefix());
  });

  // LockTime and Expiry
  var buf = new Buffer(4);
  buf.writeUInt32LE(this.lock_time, 0);
  bufs.push(buf);
  
  var buf = new Buffer(4);
  buf.writeUInt32LE(this.expiry, 0);
  bufs.push(buf);

  // TxOuts
  bufs.push(util.varIntBuf(this.outs.length));
  this.outs.forEach(function(txout) {
    bufs.push(txout.serialize());
  });
  
  // TxIns (Suffix)
  bufs.push(util.varIntBuf(this.ins.length));
  this.ins.forEach(function(txin) {
    bufs.push(txin.serializeWitness());
  });

  this._buffer = Buffer.concat(bufs);
  return this._buffer;
};

Transaction.prototype.serializePrefix = function serializePrefix() {
  // Transaction prefix buffer writer.
  var writer = new BufferWriter();
  // Should really write this.version, but there's only one version 
  // of tx right now plus the serialization types.
  writer.writeUInt32LE(CURRENT_PREFIX_VER);
  writer.writeVarintNum(this.ins.length);
  _.each(this.ins, function(input) {
    input.toBufferWriterNoScript(writer);
  });
  writer.writeVarintNum(this.outs.length);
  _.each(this.outs, function(output) {
    output.toBufferWriter(writer);
  });
  writer.writeUInt32LE(this.lock_time);
  writer.writeUInt32LE(this.expiry);
  this._buffer = writer.toBuffer();
  return this._buffer;
};

// Transaction witness buffer writer.
Transaction.prototype.serializeWitness = function serializeWitness() {
  var writer = new BufferWriter();
  // Should really write this.version, but there's only one version 
  // of tx right now plus the serialization types.
  writer.writeUInt32LE(CURRENT_WITNESS_VER);
  writer.writeVarintNum(this.ins.length);
  _.each(this.ins, function(input) {
    input.toBufferWriterScriptOnly(writer);
  });
  this._buffer = writer.toBuffer();
  return this._buffer;
};

Transaction.prototype.getBuffer = function getBuffer() {
  //if (this._buffer) return this._buffer;

  return this.serializePrefix();
};

Transaction.prototype.calcHash = function calcHash() {
  this.hash = blake256(this.getBuffer());
  return this.hash;
};

Transaction.prototype.checkHash = function checkHash() {
  if (!this.hash || !this.hash.length) return false;

  return buffertools.compare(this.calcHash(), this.hash) === 0;
};

Transaction.prototype.getHash = function getHash() {
  if (!this.hash || !this.hash.length) {
    this.hash = this.calcHash();
  }
  return this.hash;
};


Transaction.prototype.calcNormalizedHash = function() {
  this.normalizedHash = this.hashForSignature(new Script(), 0, SIGHASH_ALL);
  return this.normalizedHash;
};


Transaction.prototype.getNormalizedHash = function() {
  if (!this.normalizedHash || !this.normalizedHash.length) {
    this.normalizedHash = this.calcNormalizedHash();
  }
  return this.normalizedHash;
};



// convert encoded list of inputs to easy-to-use JS list-of-lists
Transaction.prototype.inputs = function inputs() {
  var res = [];
  for (var i = 0; i < this.ins.length; i++) {
    var txin = this.ins[i];
    var outHash = txin.getOutpointHash();
    var outIndex = txin.getOutpointIndex();
    res.push([outHash, outIndex]);
  }

  return res;
};

Transaction.prototype.verifyInput = function verifyInput(n, scriptPubKey, opts, callback) {
  var scriptSig = this.ins[n].getScript();
  return ScriptInterpreter.verifyFull(
    scriptSig,
    scriptPubKey,
    this, n, 0,
    opts,
    callback);
};

/**
 * Returns an object containing all pubkey hashes affected by this transaction.
 *
 * The return object contains the base64-encoded pubKeyHash values as keys
 * and the original pubKeyHash buffers as values.
 */
Transaction.prototype.getAffectedKeys = function getAffectedKeys(txCache) {
  // TODO: Function won't consider results cached if there are no affected
  //       accounts.
  if (!(this.affects && this.affects.length)) {
    this.affects = [];

    // Index any pubkeys affected by the outputs of this transaction
    for (var i = 0, l = this.outs.length; i < l; i++) {
      var txout = this.outs[i];
      var script = txout.getScript();

      var outPubKey = script.simpleOutPubKeyHash();
      if (outPubKey) {
        this.affects.push(outPubKey);
      }
    };

    // Index any pubkeys affected by the inputs of this transaction
    var txIndex = txCache.txIndex;
    for (var i = 0, l = this.ins.length; i < l; i++) {
      var txin = this.ins[i];

      if (txin.isCoinBase()) continue;

      // In the case of coinbase or IP transactions, the txin doesn't
      // actually contain the pubkey, so we look at the referenced txout
      // instead.
      var outHash = txin.getOutpointHash();
      var outIndex = txin.getOutpointIndex();
      var outHashBase64 = outHash.toString('base64');
      var fromTxOuts = txIndex[outHashBase64];

      if (!fromTxOuts) {
        throw new Error("Input not found!");
      }

      var txout = fromTxOuts[outIndex];
      var script = txout.getScript();

      var outPubKey = script.simpleOutPubKeyHash();
      if (outPubKey) {
        this.affects.push(outPubKey);
      }
    }
  }

  var affectedKeys = {};

  this.affects.forEach(function(pubKeyHash) {
    affectedKeys[pubKeyHash.toString('base64')] = pubKeyHash;
  });

  return affectedKeys;
};

var OP_CODESEPARATOR = 171;

var SIGHASH_ALL = Transaction.SIGHASH_ALL = ScriptInterpreter.SIGHASH_ALL;
var SIGHASH_NONE = Transaction.SIGHASH_NONE = ScriptInterpreter.SIGHASH_NONE;
var SIGHASH_SINGLE = Transaction.SIGHASH_SINGLE = ScriptInterpreter.SIGHASH_SINGLE;
var SIGHASH_ANYONECANPAY = Transaction.SIGHASH_ANYONECANPAY = ScriptInterpreter.SIGHASH_ANYONECANPAY;

var TransactionSignatureSerializer = function(txTo, scriptCode, nIn, nHashType) {
  this.txTo = txTo;
  this.scriptCode = scriptCode;
  this.nIn = nIn;
  this.anyoneCanPay = !!(nHashType & SIGHASH_ANYONECANPAY);
  var hashTypeMode = nHashType & 0x1f;
  this.hashSingle = hashTypeMode === SIGHASH_SINGLE;
  this.hashNone = hashTypeMode === SIGHASH_NONE;
  this.bytes = new Put();
};

// serialize an output of txTo
TransactionSignatureSerializer.prototype.serializeOutput = function(nOutput) {
  if (this.hashSingle && nOutput != this.nIn) {
    // Do not lock-in the txout payee at other indices as txin
    // ::Serialize(s, CTxOut(), nType, nVersion);
    this.bytes.put(util.INT64_MAX);
    this.bytes.varint(0);
  } else {
    //::Serialize(s, txTo.vout[nOutput], nType, nVersion);
    var out = this.txTo.outs[nOutput];
    this.bytes.put(out.v);
    this.bytes.varint(out.s.length);
    this.bytes.put(out.s);
  }
};

// serialize the script
TransactionSignatureSerializer.prototype.serializeScriptCode = function() {
  this.scriptCode.findAndDelete(OP_CODESEPARATOR);
  this.bytes.varint(this.scriptCode.buffer.length);
  this.bytes.put(this.scriptCode.buffer);
};

// serialize an input of txTo
TransactionSignatureSerializer.prototype.serializeInput = function(nInput) {
  // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
  if (this.anyoneCanPay) nInput = this.nIn;

  // Serialize the prevout
  this.bytes.put(this.txTo.ins[nInput].o);

  // Serialize the script
  if (nInput !== this.nIn) {
    // Blank out other inputs' signatures
    this.bytes.varint(0);
  } else {
    this.serializeScriptCode();
  }
  // Serialize the nSequence
  if (nInput !== this.nIn && (this.hashSingle || this.hashNone)) {
    // let the others update at will
    this.bytes.word32le(0);
  } else {
    this.bytes.word32le(this.txTo.ins[nInput].q);
  }

};


// serialize txTo for signature
TransactionSignatureSerializer.prototype.serialize = function() {
  // serialize nVersion
  this.bytes.word32le(this.txTo.version);
  // serialize vin
  var nInputs = this.anyoneCanPay ? 1 : this.txTo.ins.length;
  this.bytes.varint(nInputs);
  for (var nInput = 0; nInput < nInputs; nInput++) {
    this.serializeInput(nInput);
  }
  // serialize vout
  var nOutputs = this.hashNone ? 0 : (this.hashSingle ? this.nIn + 1 : this.txTo.outs.length);
  this.bytes.varint(nOutputs);
  for (var nOutput = 0; nOutput < nOutputs; nOutput++) {
    this.serializeOutput(nOutput);
  }

  // serialize nLockTime
  this.bytes.word32le(this.txTo.lock_time);
  
  // serialize expiry
  this.bytes.word32le(this.txTo.expiry);
};

TransactionSignatureSerializer.prototype.buffer = function() {
  this.serialize();
  return this.bytes.buffer();
};

Transaction.Serializer = TransactionSignatureSerializer;

var oneBuffer = function() {
  // bug present in bitcoind which must be also present in bitcore
  // see https://bitcointalk.org/index.php?topic=260595
  var ret = new Buffer(32);
  ret.writeUInt8(1, 0);
  for (var i = 1; i < 32; i++) ret.writeUInt8(0, i);
  return ret; // return 1 bug
};

Transaction.prototype.getHashType = function(inIndex) {
  preconditions.checkArgument(inIndex < this.ins.length);
  var input = this.ins[inIndex];
  var scriptSig = input.getScript();
  return scriptSig.getHashType();
};

Transaction.prototype.hashForSignature =
  function hashForSignature(script, inIndex, hashType) {

    if (+inIndex !== inIndex ||
      inIndex < 0 || inIndex >= this.ins.length) {
      return oneBuffer();
    }
    // Check for invalid use of SIGHASH_SINGLE
    var hashTypeMode = hashType & 0x1f;
    if (hashTypeMode === SIGHASH_SINGLE) {
      if (inIndex >= this.outs.length) {
        return oneBuffer();
      }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    var serializer = new TransactionSignatureSerializer(this, script, inIndex, hashType);
    // Serialize
    var buffer = serializer.buffer();
    // Append hashType
    var hashBuf = new Put().word32le(hashType).buffer();
    buffer = Buffer.concat([buffer, hashBuf]);
    return util.twoSha256(buffer);
};

/**
 * Returns an object with the same field names as jgarzik's getblock patch.
 */
Transaction.prototype.getStandardizedObject = function getStandardizedObject() {
  var tx = {
    hash: util.formatHashFull(this.getHash()),
    version: this.version,
    lock_time: this.lock_time,
    expiry: this.expiry
  };

  var totalSize = 12; // version + lock_time + expiry
  totalSize += util.getVarIntSize(this.ins.length); // tx_in count
  var ins = this.ins.map(function(txin) {
    var txinObj = {
      prev_out: {
        hash: buffertools.reverse(new Buffer(txin.getOutpointHash())).toString('hex'),
        n: txin.getOutpointIndex()
      },
      sequence: txin.q
    };
    if (txin.isCoinBase()) {
      txinObj.coinbase = txin.s.toString('hex');
    } else {
      txinObj.scriptSig = new Script(txin.s).getStringContent(false, 0);
    }
    totalSize += 37 + util.getVarIntSize(txin.s.length) +
      txin.s.length + 4; // outpoint + script_len + script + sequence
    return txinObj;
  });

  totalSize += util.getVarIntSize(this.outs.length);
  var outs = this.outs.map(function(txout) {
    totalSize += util.getVarIntSize(txout.s.length) +
      txout.s.length + 8; // script_len + script + value
    return {
      value: util.formatValue(txout.v),
      scriptPubKey: new Script(txout.s).getStringContent(false, 0)
    };
  });

  tx.size = totalSize;

  tx["in"] = ins;
  tx["out"] = outs;

  return tx;
};

// Add some Mongoose compatibility functions to the plain object
Transaction.prototype.toObject = function toObject() {
  return this;
};

Transaction.prototype.fromObj = function fromObj(obj) {
  var txobj = {};
  txobj.version = obj.version || 1;
  txobj.lock_time = obj.lock_time || 0;
  txobj.expiry = obj.expiry || 0;
  txobj.ins = [];
  txobj.outs = [];

  obj.inputs.forEach(function(inputobj) {
    var txin = new TransactionIn();
    txin.s = util.EMPTY_BUFFER;
    txin.q = 0xffffffff;

    var hash = new Buffer(inputobj.txid, 'hex');
    hash = buffertools.reverse(hash);
    var vout = parseInt(inputobj.vout);
    var voutBuf = new Buffer(4);
    voutBuf.writeUInt32LE(vout, 0);

    txin.o = Buffer.concat([hash, voutBuf]);

    txobj.ins.push(txin);
  });

  var keys = Object.keys(obj.outputs);
  keys.forEach(function(addrStr) {
    var addr = new Address(addrStr);
    var script = Script.createPubKeyHashOut(addr.payload());

    var valueNum = bignum(obj.outputs[addrStr]);
    var value = util.bigIntToValue(valueNum);

    var txout = new TransactionOut();
    txout.v = value;
    txout.s = script.getBuffer();

    txobj.outs.push(txout);
  });

  this.lock_time = txobj.lock_time;
  this.expiry = txobj.expiry;
  this.version = txobj.version;
  this.ins = txobj.ins;
  this.outs = txobj.outs;
};

Transaction.prototype.parseWithParser = function(parser) {
  if (Buffer.isBuffer(parser)) {
    this._buffer = parser;
    parser = new Parser(parser);
  }
  var i, sLen, startPos = parser.pos;
  var i, sizeTxIns, sizeTxOuts, sizeTxInScripts;
  var emptyPrev = new Buffer("0000000000000000000000000000000000000000000000000000000000000000", 'hex');

  this.version = parser.word32le();
  sizeTxIns = parser.varInt();
  for (i = 0; i < sizeTxIns; i++) {
     var input = new TransactionIn();
    //outpoint
    prevTxId = parser.buffer(32);
 //   prevTxId = buffertools.reverse(prevTxId);
    outputIndex = parser.word32le();
    outputTree = parser.word8le();
    //sequence
    input.q = parser.word32le();
    //bufferwriter to properly construct input.o buffer
    var bwIn = new BufferWriter();
    bwIn.write(prevTxId);
    bwIn.writeUInt32LE(outputIndex);
    bwIn.writeUInt8(outputTree);

    input.o = bwIn.toBuffer();
    this.ins.push(input);
  }
  sizeTxOuts = parser.varInt();
  for (i = 0; i < sizeTxOuts; i++) {
      var output =  new TransactionOut();
      output.v = BN.fromBuffer(buffertools.reverse(parser.buffer(8)));
      output.vers = parser.word16le();
      var size = parser.varInt();
      if (size !== 0) {
       output.s = parser.buffer(size);
      } else {
       output.s = new Buffer([]);
      } 
      this.outs.push(output);
  }
  this.lock_time = parser.word32le();
  this.expiry = parser.word32le();
  
  sizeTxInScripts = parser.varInt();
  for (i = 0; i < sizeTxInScripts; i++) {
    this.ins[i].valuein = parser.buffer(8);
    this.ins[i].blockheight = parser.word32le();
    this.ins[i].blockindex = parser.word32le();
    sLen = parser.varInt(); // script_len
    this.ins[i].s = parser.buffer(sLen);
  }
  
  this.calcHash();
}

Transaction.prototype.parse = function(parser) {
  if (Buffer.isBuffer(parser)) {
    this._buffer = parser;
    var reader = new BufferReader(parser);
  } else {
    this._buffer = new Buffer(parser);
    var reader = new BufferReader(this._buffer);
  }
  var i, sizeTxIns, sizeTxOuts, sizeTxInScripts;
  var emptyPrev = new Buffer("0000000000000000000000000000000000000000000000000000000000000000", 'hex');

  this.version = reader.readUInt32LE();
  sizeTxIns = reader.readVarintNum();
  for (i = 0; i < sizeTxIns; i++) {
     var input = new TransactionIn();
    //outpoint
    prevTxId = reader.read(32);
    outputIndex = reader.readUInt32LE();
    outputTree = reader.readUInt8();
    //sequence
    input.q = reader.readUInt32LE();
    //bufferwriter to properly construct input.o buffer
    var bwIn = new BufferWriter();
    bwIn.write(prevTxId);
    bwIn.writeUInt32LE(outputIndex);
    bwIn.writeUInt8(outputTree);
    input.o = bwIn.toBuffer();
    

    this.ins.push(input);
  }

  sizeTxOuts = reader.readVarintNum();
  for (i = 0; i < sizeTxOuts; i++) {
      var output =  new TransactionOut();
      output.v = reader.readUInt64LEBN();
      output.vers = reader.readUInt16LE();
      var size = reader.readVarintNum();
      if (size !== 0) {
       output.s = reader.read(size);
      } else {
       output.s = new Buffer([]);
      } 
      this.outs.push(output);
  }
  this.lock_time = reader.readUInt32LE();
  this.expiry = reader.readUInt32LE();
  sizeTxInScripts = reader.readVarintNum();
  for (i = 0; i < sizeTxInScripts; i++) {
    this.ins[i].valuein = reader.readUInt64LEBN();
    this.ins[i].blockheight = reader.readUInt32LE();
    this.ins[i].blockindex = reader.readUInt32LE();
    this.ins[i].s = reader.readVarLengthBuffer();
  }
  
  this.calcHash();
  return this;
};

Transaction.prototype.calcSize = function() {
  var totalSize = 12; // version + lock_time + expiry
  
  // prefix
  totalSize += util.getVarIntSize(this.ins.length); // tx_in count pre
  this.ins.forEach(function(txin) {
    totalSize += 37 + util.getVarIntSize(txin.s.length) +
      txin.s.length + 4; // outpoint + script_len + script + sequence
  });

  totalSize += util.getVarIntSize(this.outs.length);
  this.outs.forEach(function(txout) {
    totalSize += util.getVarIntSize(txout.s.length) +
      txout.s.length + 8; // script_len + script + value
  });

  // suffix  
  totalSize += util.getVarIntSize(this.ins.length); // tx_in count suf
  this.ins.forEach(function(txin) {
    totalSize += util.getVarIntSize(txin.s.length) +
      txin.s.length
  });
  
  this.size = totalSize;
  return totalSize;
};

Transaction.prototype.getSize = function() {
  if (!this.size) {
    this.size = this.calcSize();
  }
  return this.size;
};

Transaction.prototype.countInputSignatures = function(index) {
  var ret = 0;
  var script = new Script(this.ins[index].s);
  return script.countSignatures();
};

// Works on p2pubkey, p2pubkeyhash & p2sh (no normal multisig)
Transaction.prototype.countInputMissingSignatures = function(index) {
  var ret = 0;
  var script = new Script(this.ins[index].s);
  return script.countMissingSignatures();
};

// Works on p2pubkey, p2pubkeyhash & p2sh (no normal multisig)
Transaction.prototype.isInputComplete = function(index) {
  var m = this.countInputMissingSignatures(index);
  if (m === null) return null;
  return m === 0;
};

// Works on p2pubkey, p2pubkeyhash & p2sh (no normal multisig)
Transaction.prototype.isComplete = function() {
  var ret = true;
  var l = this.ins.length;

  for (var i = 0; i < l; i++) {
    if (!this.isInputComplete(i)) {
      ret = false;
      break;
    }
  }
  return ret;
};

Transaction.prototype.getReceivingAddresses = function(networkName) {
  if (!networkName) networkName = 'livenet';
  ret = [];
  for (var i = 0; i<this.outs.length; i++) {
    var o = this.outs[i];
    var addrs = Address.fromScriptPubKey(o.getScript(), networkName);
    if (typeof addrs[0] !== 'undefined') {
      ret.push(addrs[0].toString());
    } else {
      ret.push(null);
    }
  }
  return ret;
};

Transaction.prototype.getSendingAddresses = function(networkName) {
  if (!networkName) networkName = 'livenet';
  var ret = [];
  for (var i = 0; i<this.ins.length; i++) {
    var input = this.ins[i];
    var scriptSig = input.getScript();
    if (scriptSig.getBuffer().length === 0) {
      ret.push(null);
      continue;
    }
    var addr = Address.fromScriptSig(scriptSig, networkName);
    ret.push(addr?addr.toString():null);
  }
  return ret;
};

TransactionIn.prototype.toBufferWriterNoScript = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  writer.write(this.o);
  writer.writeUInt32LE(this.q);
  return writer;
};
TransactionOut.prototype.toBufferWriter = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  // Script version.
  var vbuf = new Buffer(2);
  vbuf.writeUInt16LE(0x0000, 0);  
  // value
  writer.writeUInt64LEBN(this.v);
  // ???
  writer.writeUInt16LE(0);
  // script length
  writer.writeVarintNum(this.s.length);
  // script
  writer.write(this.s);
  return writer;
};
module.exports = Transaction;
