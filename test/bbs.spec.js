const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, addCache} = require('../lib/index');
const expect = require('chai').expect; 
const bs58 = require('bs58');

const { Bls12381G2KeyPair } = require("@mattrglobal/jsonld-signatures-bbs")

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

const SIGNED_TEST_PAYLOAD = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/pathogen/v1',
    'https://w3id.org/security/bbs/v1'
  ],
  id: 'http://example.org/credentials/',
  type: [ 'VerifiableCredential' ],
  expirationDate: '2021-02-05T20:29:37Z',
  issuer: 'did:example:489398593',
  issuanceDate: '2021-05-18T18:52:06.304Z',
  credentialSubject: {
    type: 'DGCProofOfCovidTest',
    testInformation: {
      type: 'DGCTestInformation',
      testType: 'loinc#LP217198-3',
      testResult: 'POS',
      testCenter: 'Hospital Na Františku Prague',
      testValidatorId: 'test-id',
      countryOfTestAdminstration: 'it'
    },
    personalInformation: {
      type: 'DGCSubject',
      familyName: 'Schmidt',
      givenName: 'Abdiel',
      birthDate: '1987-07-07',
      gender: 'F'
    }
  },
  proof: {
    type: 'BbsBlsSignature2020',
    created: '2021-05-18T18:52:06Z',
    proofPurpose: 'assertionMethod',
    proofValue: 'rKKL9TwhrWdpmQRxDgptPQBFp4scxBMDkVll1L1mU8oKZ0LhRirx5dUkMGPyhmMsMm66D09Dc49bkyh8bFLsd4E9UapTEx/CEdQc+rW95XQu9CShuqj1m8hV1yUv09MV7mR2qnISjA8006gQv4wd9w==',
    verificationMethod: 'did:example:489398593#test'
  }
};

const mockKeyPair = {
  id: "did:example:489398593#test",
  controller: "did:example:489398593",
  privateKeyBase58: "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj",
  publicKeyBase58: "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
}

addCache(mockKeyPair);

describe('BBS Crypto', function() {
  it('should sign the package', async function() {
    const signed = await sign(TEST_PAYLOAD, mockKeyPair);
    expect(signed).to.not.be.null;
    expect(signed.proof).to.not.be.null;
    expect(signed.issuer).to.not.be.null;
    expect(signed.issuanceDate).to.not.be.null;
  });

  it('should verify the package', async function() {
    const result = await verify(SIGNED_TEST_PAYLOAD);
    expect(result).to.be.true;
  });

  it('should sign and verify the package with new ramdom key', async function() {
    const privateKey = await Bls12381G2KeyPair.generate({id: "did:example:489398594#test2", controller: "did:example:489398594"});

    const keyPair = {
        id: privateKey.id,
        controller: privateKey.controller,
        privateKeyBase58: bs58.encode(privateKey.privateKeyBuffer),
        publicKeyBase58: bs58.encode(privateKey.publicKeyBuffer)
    }

    addCache(keyPair);
  
    const signed = await sign(TEST_PAYLOAD, keyPair);
    const result = await verify(signed);
    expect(result).to.be.true;
  });

});

describe('BBS Data Minimization', function() {
  it('should pack And unpack', async function() {
    const packed = await pack(SIGNED_TEST_PAYLOAD);
    const unpacked = await unpack(packed);
    expect(unpacked).to.eql(SIGNED_TEST_PAYLOAD);
  });
});


describe('BBS Soup to Nuts', function() {
  it('should Sign Pack And Unpack Verify JSON', async function() {
    const uri = await signAndPack(TEST_PAYLOAD, mockKeyPair);

    console.log(uri);

    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });
});
