# decredjs-lib examples

```
var Decred = require('decredjs-lib')
```

## Generate a random address

```javascript
// dcrdtestnet for default
var privateKey = new Decred.PrivateKey(); // or new Decred.PrivateKey(null, 'dcrdtestnet');
var address = privateKey.toAddress();

// dcrdlivenet
var privateKey = new Decred.PrivateKey(null, 'dcrdlivenet');
var address = privateKey.toAddress();

```

## Export PrivateKey to Wif

```javascript
var privateKey = new Decred.PrivateKey();
privateKey.toWIF()
```

## Generate a address from a SHA256 hash
```javascript
var value = new Buffer('correct horse battery staple');
var hash = Decred.crypto.Hash.sha256(value);
var bn = Decred.crypto.BN.fromBuffer(hash);

var address = new Decred.PrivateKey(bn).toAddress();
```

## Import an address via WIF
```javascript
var wif = 'AEQvtsoBwcyojhMdeC55Tm76dtZD4yVaZL7DdtrjGgVJt4T2umzA9';

var address = new Decred.PrivateKey(wif).toAddress();
```

## Create a Transaction

```javascript
var wif = 'AERPtX9jCnwBECDhfGfJUVuzgAp9wnQSdtga8LGydNVesnjrqJhga';
var privateKey = new Decred.PrivateKey(wif)
var address = privateKey.toAddress();

var utxo = {"address":"TsnA4r7sxpMnsVMHMiZnvcNTyneeFsz3GVF","txid":"a1fa70e9aa22e014743b1cda53551f44f5e4ef9038be3870087153720d3de943","vout":0,"scriptPubKey":"76a914e7daf0befc15b6207cb12ab6bbf354b379d3f43b88ac","height":107209,"amount":199.9999,"satoshis":19999990000,"confirmations":5}
var transaction = new Decred.Transaction()
  .from(utxo)
  .to('TcZzyn89mrSHUv5bxfkTan8VvQCxwkkSpFK', 10 * 1e8)
  .change(address.toString())
  .sign(privateKey);

console.log(transaction.serialize())
console.log(JSON.stringify(transaction.toJSON(), null, 4))
```

## Create an OP RETURN transaction

```javascript
var wif = 'AERPtX9jCnwBECDhfGfJUVuzgAp9wnQSdtga8LGydNVesnjrqJhga';
var privateKey = new Decred.PrivateKey(wif)
var address = privateKey.toAddress();

var utxo = {"address":"TsnA4r7sxpMnsVMHMiZnvcNTyneeFsz3GVF","txid":"a1fa70e9aa22e014743b1cda53551f44f5e4ef9038be3870087153720d3de943","vout":0,"scriptPubKey":"76a914e7daf0befc15b6207cb12ab6bbf354b379d3f43b88ac","height":107209,"amount":199.9999,"satoshis":19999990000,"confirmations":5}
var transaction = new Decred.Transaction()
  .from(utxo)
  .to('TcZzyn89mrSHUv5bxfkTan8VvQCxwkkSpFK', 10 * 1e8)
  .change(address.toString())
  .addData('Hello, Decred.') // OP_RETURN
  .sign(privateKey);

console.log(transaction.serialize())
console.log(JSON.stringify(transaction.toJSON(), null, 4))
```

## Create a 2-of-3 multisig P2SH address
```javascript
var publicKeys = [
  '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
  '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
  '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9'
];
var requiredSignatures = 2;

var address = new Decred.Address(publicKeys, requiredSignatures);
```

## Spend from a 2-of-2 multisig P2SH address
```javascript
var privateKeys = [
  new Decred.PrivateKey('10c5a8d45bd94fa424fbd020b48b73b9e62bf663a46ef8689051b949583906ef'),
  new Decred.PrivateKey('8a415ab2d8289e4a1db1b9eca59eee0336617da427e2a8815cce11b6d8a14120')
];
var publicKeys = privateKeys.map(Decred.PublicKey);
var address = new Decred.Address(publicKeys, 2); // 2 of 2

var utxo = {
  "txId" : "a1fa70e9aa22e014743b1cda53551f44f5e4ef9038be3870087153720d3de943",
  "outputIndex" : 0,
  "address" : address.toString(),
  "script" : new Decred.Script(address).toHex(),
  "atoms" : 20000
};

var transaction = new Decred.Transaction()
    .from(utxo, publicKeys, 2)
    .to('TcZzyn89mrSHUv5bxfkTan8VvQCxwkkSpFK', 19000)
    .sign(privateKeys);
    
console.log(transaction.serialize())
```

## Generate a random mnemonic

```javascript
var mn = new Decred.Mnemonic()
var words = mn.toString()
console.log(words)
```

## Create a BIP44, decred, account 0, external address from a random mnemonic

```javascript
var mn = new Decred.Mnemonic()
var path = "m/44'/42'/0'/0/0"
var child = mn.toHDPrivateKey('dcrdtestnet').derive(path)
var data = {
    path: path,
    privateKey: child.privateKey.toString(),
    publicKey: child.publicKey.toString(),
    address: child.publicKey.toAddress().toString()
}
console.log(data)
```

## Export xPrivKey/xPubKey from mnemonic

```javascript
var words = 'stockman universe transit glossary beeswax pharmacy Christmas dictator crumpled visitor mural Atlantic drunken paragon tunnel telephone regain decimal waffle liberty uncut insurgent tycoon Virginia pupil company snapline corrosion stockman applicant village liberty scenic'
var mn = new Decred.Mnemonic(words)
var root = mn.toHDPrivateKey('dcrdlivenet')
console.log(root.xprivkey) // dprv3hCznBesA6jBuNNdAXH3Zh2Egiqfg5RxBd1SSLULDJ6GrrHE2RGw7tCgD5Rdo3M6nkzd7gW8jHYPfYZywMCnaVnACdhkffWFU92phVHWM9k
console.log(root.xpubkey) // dpubZ9169KDAEUnyonGPR3LQ5upVJjPw7222PAdmBFQhDNguaQJruNcYCTihMnXj8vUgeXvo5bbZavXxbZ8rgSsG2p9GBWd17SZRxhWFyu8KGsq
```

## Generate address by HDPrivateKey/HDPublicKey derive

```javascript
var xPrivKey = 'dprv3hCznBesA6jBuNNdAXH3Zh2Egiqfg5RxBd1SSLULDJ6GrrHE2RGw7tCgD5Rdo3M6nkzd7gW8jHYPfYZywMCnaVnACdhkffWFU92phVHWM9k'
var basePath = "m/44'/42'/0'/0"
var root2 = new Decred.HDPrivateKey(xPrivKey).derive(basePath)
var root3 = new Decred.HDPublicKey(root2.xpubkey)
var data = {
    // "m/44'/42'/0'/0/0"
    address: root2.derive(0).publicKey.toAddress().toString(), // get address by HDPrivateKey derive
    // "m/44'/42'/0'/0/0"
    address2: root3.derive(0).publicKey.toAddress().toString(), // get address by HDPublicKey derive
    // "m/44'/42'/0'/0/1"
    address3: root3.derive(1).publicKey.toAddress().toString(), // get address by HDPublicKey derive
}
console.log(data)
```


