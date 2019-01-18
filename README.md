DecredJS (decredjs-lib)
=======

Warning: Project under development, please do not use in a production environment.

<!--
[![NPM Package](https://img.shields.io/npm/v/bitcore.svg?style=flat-square)](https://www.npmjs.org/package/bitcore)
[![Build Status](https://img.shields.io/travis/bitpay/bitcore.svg?branch=master&style=flat-square)](https://travis-ci.org/bitpay/bitcore)
[![Coverage Status](https://img.shields.io/coveralls/bitpay/bitcore.svg?style=flat-square)](https://coveralls.io/r/bitpay/bitcore)
-->

A pure and powerful JavaScript Decred library.

## Principles

Decred is a powerful new peer-to-peer platform for the next generation of financial technology. The decentralized nature of the Decred network allows for highly resilient decred infrastructure, and the developer community needs reliable, open-source tools to implement decred apps and services.

## Get Started

For nodejs:

```
npm install decredjs-lib
```

For browser please download [decredjs-lib.min.js](https://github.com/decredjs/decredjs-lib/blob/master-new/decredjs-lib.min.js) and see the [demo](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/browser.md)

## Examples

* [Generate a random address](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#generate-a-random-address)
* [Generate a address from a SHA256 hash](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#generate-a-address-from-a-sha256-hash)
* [Import an address via WIF](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#import-an-address-via-wif)
* [Create a Transaction](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#create-a-transaction)
* [Create an OP RETURN transaction](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#create-an-op-return-transaction)
* [Create a 2-of-3 multisig P2SH address](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#create-a-2-of-3-multisig-p2sh-address)
* [Spend from a 2-of-2 multisig P2SH address](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#spend-from-a-2-of-2-multisig-p2sh-address)
* [Generate a random mnemonic](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#generate-a-random-mnemonic)
* [Create a BIP44, decred, account 0, external address from a random mnemonic](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#create-a-bip44-decred-account-0-external-address-from-a-random-mnemonic)
* [Export xPrivKey/xPubKey from mnemonic](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#export-xprivkeyxpubkey-from-mnemonic)
* [Generate address by HDPrivateKey/HDPublicKey derive](https://github.com/decredjs/decredjs-lib/blob/master-new/docs/examples.md#generate-address-by-hdprivatekeyhdpublickey-derive)

## Development & Tests

```sh
git clone https://github.com/decredjs/decredjs-lib
cd decredjs-lib
npm install
```

Run all the tests:

```sh
gulp test
```

You can also run just the Node.js tests with `gulp test:node`, just the browser tests with `gulp test:browser`
or create a test coverage report (you can open `coverage/lcov-report/index.html` to visualize it) with `gulp coverage`.

## Building the Browser Bundle

To build a decredjs-lib full bundle for the browser:

```sh
gulp browser
```

This will generate files named `decredjs-lib.js` and `decredjs-lib.min.js`.

You can also use our pre-generated files, provided for each release along with a PGP signature by one of the project's maintainers. To get them, checkout a release commit (for example, https://github.com/decredjs/decredjs-lib/commit/e33b6e3ba6a1e5830a079e02d949fce69ea33546 for v0.12.6).

To verify signatures, use the following PGP keys:
- @braydonf: https://pgp.mit.edu/pks/lookup?op=get&search=0x9BBF07CAC07A276D
- @pnagurny: https://pgp.mit.edu/pks/lookup?op=get&search=0x0909B33F0AA53013

## Contributing

Please send pull requests for bug fixes, code optimization, and ideas for improvement. For more information on how to contribute, please refer to our [CONTRIBUTING](https://github.com/decredjs/decredjs-lib/blob/master-new/CONTRIBUTING.md) file.


## License

Code released under [the MIT license](https://github.com/decredjs/decredjs-lib/blob/master-new/LICENSE).

