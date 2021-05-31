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
  "type": [
    "VerifiableCredential"
  ],
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
  issuer: 'did:web:PCF.PW:1A8',
  issuanceDate: '2021-05-20T19:33:43.346Z',
  expirationDate: '2023-05-20T04:00:00.000Z',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/pathogen/v1',
    'https://w3id.org/security/bbs/v1'
  ],
  type: [ 'VerifiableCredential' ],
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
    created: '2021-05-20T19:33:43Z',
    proofPurpose: 'assertionMethod',
    proofValue: 'ktP+YZ3/MnXkb9CQWn873Te0N/nEmDpFBEh69nLc/RnaVCuh6cKs2dFvhsSVEeJ1YSAOyasVSGRCzDJyMoG0SMiYhFqHtC6EHgQipO8gH7wQX7iiqKxTzgYLuji0j6BUW2JQOjB4XtP7m36gw0+g+g==',
    verificationMethod: 'did:web:PCF.PW:1A8#DEMO'
  }
};

const mockKeyPair = {
  id: "did:web:PCF.PW:1A8#DEMO",
  controller: "did:web:PCF.PW:1A8",
  privateKeyBase58: "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj",
  publicKeyBase58: "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
}

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
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });
});


const DGCProofOfRecovery = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/pathogen/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "credentialSubject": {
    "@context": [
      "https://w3id.org/pathogen/v1"
    ],
    "type": "DGCProofOfRecovery",
    "id": "urn:uvci:01:NL:LSP/REC/1289821",
    "infectionInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCInfectionInformation",
      "countryOfTest": "NL",
      "dateFirstPositive": "2021-04-21",
      "diseaseRecoveredFrom": "840539006"
    },
    "issuerName": "Ministry of VWS",
    "personalInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCSubject",
      "birthDate": "2009-02-28",
      "familyName": "d'ArsÃ¸ns - van Halen",
      "givenName": "FranÃ§ois-Joan",
      "stdFamilyName": "DARSONS<VAN<HALEN",
      "stdGivenName": "FRANCOIS<JOAN"
    },
    "validFrom": "2021-05-01",
    "validUntil": "2021-10-21"
  }
}

const DGCProofOfCovidTest = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/pathogen/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "credentialSubject": {
    "@context": [
      "https://w3id.org/pathogen/v1"
    ],
    "type": "DGCProofOfCovidTest",
    "id": "urn:uvci:01:NL:GGD/81AAH16AZ",
    "issuerName": "Ministry of VWS",
    "personalInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCSubject",
      "birthDate": "2009-02-28",
      "familyName": "d'ArsÃ¸ns - van Halen",
      "givenName": "FranÃ§ois-Joan",
      "stdFamilyName": "DARSONS<VAN<HALEN",
      "stdGivenName": "FRANCOIS<JOAN"
    },
    "testInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCTestInformation",
      "countryOfTestAdminstration": "NL",
      "diseaseTestedFrom": "840539006",
      "sampleCollectionDateTime": "2021-04-13T14:20:00+00:00",
      "testCenter": "GGD FryslÃ¢n, L-Heliconweg",
      "testManufacturer": "1232",
      "testName": "COVID PCR",
      "testResult": "260415000",
      "testResultDate": "2021-04-13T14:40:01+00:00",
      "testType": "LP217198-3"
    }
  }
}

const DGCProofOfVaccination = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/pathogen/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "credentialSubject": {
    "@context": [
      "https://w3id.org/pathogen/v1"
    ],
    "type": "DGCProofOfVaccination",
    "id": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ",
    "issuerName": "Ministry of VWS",
    "personalInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCSubject",
      "birthDate": "2009-02-28",
      "familyName": "d'ArsÃ¸ns - van Halen",
      "givenName": "FranÃ§ois-Joan",
      "stdFamilyName": "DARSONS<VAN<HALEN",
      "stdGivenName": "FRANCOIS<JOAN"
    },
    "vaccinationInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCVaccinationInformation",
      "countryOfVaccination": "NL",
      "dateOfVaccination": "2021-05-18",
      "diseaseProtectedFrom": "840539006",
      "order": "2 of 2",
      "prophylaxis": "1119349007",
      "vaccine": {
        "@context": [
          "https://w3id.org/pathogen/v1"
        ],
        "type": "DGCVaccine",
        "code": "1119349007",
        "marketingAuthHolder": "ORG-100030215",
        "medicinalProductName": "EU/1/20/1528"
      }
    }
  }
}

const CombinedDGC = {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/dgc/v1", "https://w3id.org/security/bbs/v1"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {
        "@context": ["https://w3id.org/dgc/v1"],
        "type": "DGCCertificate",
        "personalInformation": {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCSubject",
            "familyName": "d'Arsøns - van Halen",
            "givenName": "François-Joan",
            "stdFamilyName": "DARSONS<VAN<HALEN",
            "stdGivenName": "FRANCOIS<JOAN",
            "birthDate": "2009-02-28"
        },
        "proofOfRecovery": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfRecovery",
            "id": "urn:uvci:01:NL:LSP/REC/1289821",
            "issuerName": "Ministry of VWS",
            "countryOfTest": "NL",
            "infectionInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCInfectionInformation",
                "diseaseRecoveredFrom": "840539006",
                "dateFirstPositive": "2021-04-21",
                "validFrom": "2021-05-01",
                "validUntil": "2021-10-21"
            }
        }],
        "proofOfVaccination": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfVaccination",
            "id": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ",
            "issuerName": "Ministry of VWS",
            "countryOfVaccination": "NL",
            "vaccinationInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCVaccinationInformation",
                "diseaseProtectedFrom": "840539006",
                "prophylaxis": "1119349007",
                "dateOfVaccination": "2021-05-05",
                "dose": 1,
                "totalDoses": 2,
                "marketingAuthHolder": "ORG-100030215",
                "medicinalProductName": "EU/1/20/1528"
            }
        }, {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfVaccination",
            "id": "urn:uvci:01:NL:ATS342XDYS358FDFH3GTK5",
            "issuerName": "Ministry of VWS",
            "countryOfVaccination": "NL",
            "vaccinationInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCVaccinationInformation",
                "diseaseProtectedFrom": "840539006",
                "prophylaxis": "1119349007",
                "dateOfVaccination": "2021-05-25",
                "dose": 2,
                "totalDoses": 2,
                "marketingAuthHolder": "ORG-100030215",
                "medicinalProductName": "EU/1/20/1528"
            }
        }],
        "proofOfCovidTest": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfCovidTest",
            "id": "urn:uvci:01:NL:GGD/81AAH16AZ",
            "issuerName": "Ministry of VWS",
            "countryOfTestAdminstration": "NL",
            "testInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCTestInformation",
                "diseaseTestedFrom": "840539006",
                "testName": "COVID PCR",
                "testManufacturer": "1232",
                "testType": "LP217198-3",
                "sampleCollectionDateTime": "2021-02-13T14:20:00Z",
                "testResult": "260415000",
                "testCenter": "GGD Fryslân, L-Heliconweg"
            }
        }, {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfCovidTest",
            "id": "urn:uvci:01:NL:GGD/23BBS36BC",
            "issuerName": "Ministry of VWS",
            "countryOfTestAdminstration": "NL",
            "testInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCTestInformation",
                "diseaseTestedFrom": "840539006",
                "testName": "NAAT TEST",
                "testManufacturer": "1343",
                "testType": "LP6464-4",
                "sampleCollectionDateTime": "2021-04-13T14:20:00Z",
                "testResult": "260373001",
                "testCenter": "GGD Fryslân, L-Heliconweg"
            }
        }]
    }
};

describe('DGC Soup to Nuts', function() {
  it('should Sign Pack And Unpack Verify DGCProofOfRecovery', async function() {
    const uri = await signAndPack(DGCProofOfRecovery, mockKeyPair);
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfRecovery);
  });

  it('should Sign Pack And Unpack Verify DGCProofCOVIDTest', async function() {
    const uri = await signAndPack(DGCProofOfCovidTest, mockKeyPair);
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfCovidTest);
  });

  it('should Sign Pack And Unpack Verify DGCProofOfVaccination', async function() {
    const uri = await signAndPack(DGCProofOfVaccination, mockKeyPair);
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfVaccination);
  });

  it('should Sign Pack And Unpack Verify a Combined DGC', async function() {
    const uri = await signAndPack(CombinedDGC, mockKeyPair, "pcf.pw", "dgc", "1");
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })

    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(CombinedDGC);
  });
});
