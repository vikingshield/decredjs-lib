var util = require('../util');
var Put = require('bufferput');
var Script = require('./Script');
var Bignum = require('bignum');
var buffertools = require('buffertools');
var Transaction = require('./Transaction');
var TransactionIn = Transaction.In;
var TransactionOut = Transaction.Out;
var COINBASE_OP = Transaction.COINBASE_OP;
var VerificationError = require('../util/error').VerificationError;
var BlockRules = {
  maxTimeOffset: 2 * 60 * 60, // How far block timestamps can be into the future
  //largestHash: (new Bignum(2)).pow(256)
  //largestHash: new Bignum('115792089237316195423570985008687907853269984665640564039457584007913129639936') // = 2^256
  largestHash: new Bignum('10000000000000000000000000000000000000000000000000000000000000000', 16)
};

function Block(data) {
  if ("object" !== typeof data) {
    data = {};
  }
  this.hash = data.hash || null;
  this.prev_hash = data.prev_hash || util.NULL_HASH;
  this.merkle_root = data.merkle_root || util.NULL_HASH;
  this.stake_root = data.stake_root || util.NULL_HASH;
  this.votebits = data.votebits || 0;
  this.finalstate = data.finalstate || 0;
  this.voters = data.voters || 0;
  this.freshstake = data.freshstake || 0;
  this.revocations = data.revocations || 0;
  this.poolsize = data.poolsize || 0;
  this.timestamp = data.timestamp || 0;
  this.bits = data.bits || 0;
  this.sbits = data.sbits || 0;
  this.nonce = data.nonce || 0;
  this.version = data.version || 0;
  this.height = data.height || 0;
  this.size = data.size || 0;
  this.active = data.active || false;
  this.chainWork = data.chainWork || util.EMPTY_BUFFER;
  this.txs = data.txs || [];
  this.stx = data.stx || [];
}

Block.prototype.getHeader = function getHeader() {
  // var buf = new Buffer(180);
  var put = new Put();
  //var ofs = 0;
  put.word32le(this.version);
  //ofs += 4;
  //this.prev_hash.copy(buf, ofs);
  put.put(new Buffer(this.prev_hash, 'hex'));
  //ofs += 32;
  // this.merkle_root.copy(buf, ofs);
  put.put(new Buffer(this.merkle_root, 'hex'));
  //ofs += 32;
  // this.stake_root.copy(buf, ofs);
  put.put(new Buffer(this.stake_root, 'hex'));
  //ofs += 32;
  //buf.writeUInt16LE(this.votebits, ofs);
  put.word16le(this.votebits);
  //????
  put.put(new Buffer(this.finalstate, 'hex'));
  //ofs += 2;
  // buf.writeUInt16LE(this.voters, ofs);
  put.word16le(this.voters);
  //ofs += 2;
  // buf.writeUInt8(this.freshstake, ofs);
  put.word8(this.freshstake);
  //ofs += 1;
  // buf.writeUInt8(this.revocations, ofs);
  put.word8(this.revocations);
  //ofs += 1;
  //buf.writeUInt32LE(this.poolsize, ofs);
  put.word32le(this.poolsize);
  //ofs += 4;
  // buf.writeUInt32LE(this.bits, ofs);
  put.word32le(this.bits);
  //ofs += 4;
  // For some reason, buffer lacks int64
  // TODO probably should use bignum here instead.
  // this.sbits = (buf.readUInt32LE(ofs) << 8) + buf.readUInt32LE(ofs+4);
  //buf.writeUInt32LE(this.sbits << 32)
  //buf.writeUInt32LE(this.sbits & 0x00000000)
  put.word64le(this.sbits);
  //ofs += 8;
  // buf.writeUInt32LE(this.height, ofs);
  put.word32le(this.height);
  //ofs += 4;
  // buf.writeUInt32LE(this.size, ofs);
  put.word32le(this.size);
  //ofs += 4;
  // buf.writeUInt32LE(this.timestamp, ofs);
  put.word32le(this.timestamp);
  //ofs += 4;
  // buf.writeUInt32LE(this.nonce, ofs);
  put.word32le(this.nonce);
  //ofs += 4;
  // When we have something in ExtraData we can add it here.
  put.put(new Buffer(this.extradata, 'hex'));

  //var serializedHeader = put.buffer()
  //log.debug("serialized header: " + serializedHeader.toString(hex))
  
  return put.buffer();
};

Block.prototype.parse = function parse(parser, headerOnly) {
  this.version = parser.word32le();
  this.prev_hash = parser.buffer(32);
  this.merkle_root = parser.buffer(32);
  this.stake_root = parser.buffer(32);
  this.votebits = parser.word16le();
  this.finalstate = parser.buffer(6);
  this.voters = parser.word16le();
  this.freshstake = parser.word8le();
  this.revocations = parser.word8le();
  this.poolsize = parser.word32le();
  this.bits = parser.word32le();
  this.sbits = parser.word64le();
  this.height = parser.word32le();
  this.size = parser.word32le();
  this.timestamp = parser.word32le();
  this.nonce = parser.word32le();
  this.extradata = parser.buffer(36);
  // When we have something in ExtraData we can add it here.
  
  this.hash = this.calcHash();
  
  this.txs = [];

  if (headerOnly)
    return;

  var txCount = parser.varInt();
  for (var i = 0; i < txCount; i++) {
    var tx = new Transaction();
    tx.parseWithParser(parser);
    this.txs.push(tx);
  }

  var stxCount = parser.varInt();
  for (var i = 0; i < stxCount; i++) {
    var stx = new Transaction();
    stx.parseWithParser(parser);
    this.txs.push(stx);
  }
  
};

Block.prototype.calcHash = function calcHash() {
  var header = this.getHeader();

  return util.blake256(header);
};

Block.prototype.checkHash = function checkHash() {
  if (!this.hash || !this.hash.length) return false;
  return buffertools.compare(this.calcHash(), this.hash) == 0;
};

Block.prototype.getHash = function getHash() {
  if (!this.hash || !this.hash.length) this.hash = this.calcHash();

  return this.hash;
};

Block.prototype.checkProofOfWork = function checkProofOfWork() {
  var target = util.decodeDiffBits(this.bits);

  // TODO: Create a compare method in node-buffertools that uses the correct
  //       endian so we don't have to reverse both buffers before comparing.
  var reverseHash = buffertools.reverse(this.hash);
  if (buffertools.compare(reverseHash, target) > 0) {
    throw new VerificationError('Difficulty target not met');
  }

  return true;
};

/**
 * Returns the amount of work that went into this block.
 *
 * Work is defined as the average number of tries required to meet this
 * block's difficulty target. For example a target that is greater than 5%
 * of all possible hashes would mean that 20 "work" is required to meet it.
 */
Block.prototype.getWork = function getWork() {
  var target = util.decodeDiffBits(this.bits, true);
  return BlockRules.largestHash.div(target.add(1));
};

Block.prototype.checkTimestamp = function checkTimestamp() {
  var currentTime = new Date().getTime() / 1000;
  if (this.timestamp > currentTime + BlockRules.maxTimeOffset) {
    throw new VerificationError('Timestamp too far into the future');
  }

  return true;
};

Block.prototype.checkTransactions = function checkTransactions(txs) {
  if (!Array.isArray(txs) || txs.length <= 0) {
    throw new VerificationError('No transactions');
  }
  if (!txs[0].isCoinBase()) {
    throw new VerificationError('First tx must be coinbase');
  }
  for (var i = 1; i < txs.length; i++) {
    if (txs[i].isCoinBase()) {
      throw new VerificationError('Tx index ' + i + ' must not be coinbase');
    }
  }

  return true;
};

/**
 * Build merkle tree.
 *
 * Ported from Java. Original code: BitcoinJ by Mike Hearn
 * Copyright (c) 2011 Google Inc.
 */
Block.prototype.getMerkleTree = function getMerkleTree(txs) {
  // The merkle hash is based on a tree of hashes calculated from the transactions:
  //
  //          merkleHash
  //             /\
  //            /  \
  //          A      B
  //         / \    / \
  //       tx1 tx2 tx3 tx4
  //
  // Basically transactions are hashed, then the hashes of the transactions are hashed
  // again and so on upwards into the tree. The point of this scheme is to allow for
  // disk space savings later on.
  //
  // This function is a direct translation of CBlock::BuildMerkleTree().

  if (txs.length == 0) {
    return [util.NULL_HASH.slice(0)];
  }

  // Start by adding all the hashes of the transactions as leaves of the tree.
  var tree = txs.map(function(tx) {
    return tx instanceof Transaction ? tx.getHash() : tx;
  });

  var j = 0;
  // Now step through each level ...
  for (var size = txs.length; size > 1; size = Math.floor((size + 1) / 2)) {
    // and for each leaf on that level ..
    for (var i = 0; i < size; i += 2) {
      var i2 = Math.min(i + 1, size - 1);
      var a = tree[j + i];
      var b = tree[j + i2];
      tree.push(util.blake256(Buffer.concat([a, b])));
    }
    j += size;
  }

  return tree;
};

Block.prototype.calcMerkleRoot = function calcMerkleRoot(txs) {
  var tree = this.getMerkleTree(txs);
  return tree[tree.length - 1];
};

Block.prototype.checkMerkleRoot = function checkMerkleRoot(txs) {
  if (!this.merkle_root || !this.merkle_root.length) {
    throw new VerificationError('No merkle root');
  }

  if (buffertools.compare(this.calcMerkleRoot(txs), new Buffer(this.merkle_root)) !== 0) {
    throw new VerificationError('Merkle root incorrect');
  }

  return true;
};

Block.prototype.checkBlock = function checkBlock(txs) {
  if (!this.checkHash()) {
    throw new VerificationError("Block hash invalid");
  }
  this.checkProofOfWork();
  this.checkTimestamp();

  if (txs) {
    this.checkTransactions(txs);
    if (!this.checkMerkleRoot(txs)) {
      throw new VerificationError("Merkle hash invalid");
    }
  }
  return true;
};

Block.getBlockValue = function getBlockValue(height) {
  var subsidy = 50 * util.COIN;
  subsidy = subsidy / (Math.pow(2, Math.floor(height / 210000)));
  subsidy = Math.floor(subsidy);
  subsidy = new Bignum(subsidy);
  return subsidy;
};

Block.prototype.getBlockValue = function getBlockValue() {
  return Block.getBlockValue(this.height);
};

Block.prototype.toString = function toString() {
  return "<Block " + util.formatHashAlt(this.hash) + " height=" + this.height + ">";
};


Block.prototype.createCoinbaseTx =
  function createCoinbaseTx(beneficiary) {
    var tx = new Transaction();
    tx.ins.push(new TransactionIn({
      s: util.EMPTY_BUFFER,
      q: 0xffffffff,
      o: COINBASE_OP
    }));
    tx.outs.push(new TransactionOut({
      v: util.bigIntToValue(this.getBlockValue()),
      s: Script.createPubKeyOut(beneficiary).getBuffer()
    }));
    return tx;
};

Block.prototype.solve = function solve(miner, callback) {
  var header = this.getHeader();
  var target = util.decodeDiffBits(this.bits);
  miner.solve(header, target, callback);
};

/**
 * Returns an object with the same field names as jgarzik's getblock patch.
 */
Block.prototype.getStandardizedObject =
  function getStandardizedObject(txs) {
    var block = {
      hash: util.formatHashFull(this.getHash()),
      version: this.version,
      prev_block: util.formatHashFull(this.prev_hash),
      mrkl_root: util.formatHashFull(this.merkle_root),
      stake_root: util.formatHashFull(this.stake_root),

      votebits: this.votebits,
      finalstate: this.finalstate,
      voters: this.voters,
      freshstake: this.freshstake,
      revocations: this.revocations,
      poolsize: this.poolsize,
      time: this.timestamp,
      bits: this.bits,
      sbit: this.sbits,
      nonce: this.nonce,
      height: this.height
    };


    if (txs) {
      var mrkl_tree = this.getMerkleTree(txs).map(function(buffer) {
        return util.formatHashFull(buffer);
      });
      block.mrkl_root = mrkl_tree[mrkl_tree.length - 1];

      block.n_tx = txs.length;
      var totalSize = 180; // Block header
      totalSize += util.getVarIntSize(txs.length); // txn_count
      txs = txs.map(function(tx) {
        tx = tx.getStandardizedObject();
        totalSize += tx.size;
        return tx;
      });
      block.size = totalSize;
      block.tx = txs;

      block.mrkl_tree = mrkl_tree;
    } else {
      block.size = this.size;
    }
    return block;
};

module.exports = Block;
