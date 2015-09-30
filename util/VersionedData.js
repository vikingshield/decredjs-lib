var base58 = require('../lib/Base58').base58Check;
var util = require('util');
var EncodedData = require('./EncodedData');


function VersionedData(version, payload) {
  VersionedData.super_.call(this, version, payload);
  if (typeof version != 'number') {
    return;
  };
  this.data = new Buffer(payload.length + 2);
  this.encoding('binary');
  this.version(version);
  this.payload(payload);
};

util.inherits(VersionedData, EncodedData);
EncodedData.applyEncodingsTo(VersionedData);

// get or set the version data (the first 2 bytes of the address)
VersionedData.prototype.version = function(num) {
  if (num || (num === 0)) {
    this.doAsBinary(function() {
      this.data.writeUInt16BE(num, 0);
    });
    return num;
  }
  return this.as('binary').readUInt16BE(0);
};

// get or set the payload data (as a Buffer object)
VersionedData.prototype.payload = function(data) {
  if (data) {
    this.doAsBinary(function() {
      data.copy(this.data, 2);
    });
    return data;
  }
  return this.as('binary').slice(2);
};

module.exports = VersionedData;
