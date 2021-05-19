import { documentLoader } from './documentLoader'

import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "@mattrglobal/jsonld-signatures-bbs"

import jsigs from "jsonld-signatures";

import { encode, decode }  from 'base32url';

import * as cborld from '@digitalbazaar/cborld';

import zlib from 'pako';

var ghpAppContextMap = new Map();
ghpAppContextMap.set('https://w3id.org/pathogen/v1', 0x8FFA);
ghpAppContextMap.set('https://w3id.org/security/bbs/v1', 0x8FFB);

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
    const zippedCbor = new Uint8Array(cborldArrayBuffer);

    const cborldBytes = zlib.inflate(zippedCbor)

    const jsonld = await cborld.decode({
      cborldBytes,
      documentLoader,
      appContextMap: ghpAppContextMap
      //diagnose: console.log
    });

    return jsonld;
}    

export async function pack(signedData) {
    const cborldBytes = await cborld.encode({
      jsonldDocument: signedData,
      documentLoader,
      appContextMap: ghpAppContextMap
      //diagnose: console.log
    });

    const zippedCbor = zlib.deflate(cborldBytes)

    const encoded = encode(zippedCbor);

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
