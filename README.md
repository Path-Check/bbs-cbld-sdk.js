# Verifiable QR SDK for BBS+ on CBOR-LD Credentials

JavaScript Implementation of W3C Verifiable QR Credentials with BBS+ -> CBOR-LD -> QR. 

# Install

```sh
npm install divoc.sdk --save
```

# Usage

With the keys: 

```js
const keyPair = {
  id: "did:example:489398593#test",
  controller: "did:example:489398593",
  privateKeyBase58: "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj",
  publicKeyBase58: "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
}
```

And a JSON-LD Payload 

```js
const TEST_PAYLOAD = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/pathogen/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "id": "http://example.org/credentials/",
  "type": [
    "VerifiableCredential"
  ],
  "expirationDate": "2021-02-05T20:29:37Z",
  "credentialSubject": {
    "type": "DGCProofOfCovidTest",
    "testInformation": {
      "type": "DGCTestInformation",
      "testType": "loinc#LP217198-3",
      "testResult": "POS",
      "testCenter": "Hospital Na Františku Prague",
      "testValidatorId": "test-id",
      "countryOfTestAdminstration": "it"
    },
    "personalInformation": {
      "type": "DGCSubject",
      "familyName": "Schmidt",
      "givenName": "Abdiel",
      "birthDate": "1987-07-07",
      "gender": "F"
    }
  }
};
```

Add keys to the Resolver Cache and call the signAndPack to create the URI for the QR Code: 

```js
const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, addCache} = require('../lib/index');
addCache(mockKeyPair);

const qrUri = await signAndPack(TEST_PAYLOAD, keyPair);
```

And call the unpack and verify to convert the URI into the payload: 

```js
const jsonld = await unpackAndVerify(qrUri);
```

# Development

```sh
npm install
``` 

# Test

```sh
npm test
```
