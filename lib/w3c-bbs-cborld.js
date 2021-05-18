import { documentLoader } from './documentLoader'

import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "@mattrglobal/jsonld-signatures-bbs"

const jsigs = require("jsonld-signatures");

import { encode, decode }  from './base32URL';

import * as cborld from '@digitalbazaar/cborld';

const CBLD_SCHEMA = 'CBLD:';

export async function sign(certificate, keyPairSerialized) {
    const keyPair = await new Bls12381G2KeyPair(keyPairSerialized);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    var issue = new Date();
    var year = issue.getFullYear();
    var month = issue.getMonth();
    var day = issue.getDate();
    var exp = new Date(year + 2, month, day);

    const credential = {
        issuer: keyPairSerialized.controller,
        issuanceDate: issue.toISOString(),
        expirationDate: exp.toISOString(),
        ...certificate
    };

    return await jsigs.sign(
      credential, {
        suite, 
        purpose: new jsigs.purposes.AssertionProofPurpose(), 
        documentLoader
      }
    );
}

export async function verify(credential) {
    let verification = await jsigs.verify(credential, {
      suite: new BbsBlsSignature2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader
    });

    return verification.verified;
}

export async function unpack(text) {
    if(!(text && text.startsWith(CBLD_SCHEMA))) {
      throw TypeError('Unsupported CBLD QR format.');
    }

    const multibasePayload = text.slice(CBLD_SCHEMA.length);

    const cborldArrayBuffer = await decode(multibasePayload);
    const cborldBytes = new Uint8Array(cborldArrayBuffer);

    const jsonld = await cborld.decode({
      cborldBytes,
      documentLoader
      // appContextMap: citAppContextMap,
      //diagnose: console.log
    });

    return jsonld;
}    

export async function pack(signedData) {
    const cborldBytes = await cborld.encode({
      jsonldDocument: signedData,
      documentLoader
      //appContextMap: citAppContextMap,
      //diagnose: console.log
    });

    const encoded = encode(cborldBytes);

    const qrPayload = `${CBLD_SCHEMA}${encoded}`;

    return qrPayload;
}

export async function signAndPack(payload, did) {
  return await pack(await sign(payload, did));
}

export async function unpackAndVerify(uri) {
  try {
    const json = await unpack(uri);
    if (await verify(json)) {
      delete json["proof"];
      return json;
    }
    return undefined;
  } catch (err) {
    console.log(err);
    return undefined;
  }
}
