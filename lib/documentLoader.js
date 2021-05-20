import vaccinationContext from './context/vaccination.v1'
import credentialsContext from './context/credentials'
import securityV3Context from './context/securityV3'
import ed25519 from './context/ed25519-signature-2020-v1'
import bbs2020 from './context/bbs-signature-2020-v1'
import pathogen from './context/pathogen-v1'

import { resolveDID } from './DIDWEBResolver.js'

var contexts = {
  "https://www.w3.org/2018/credentials/v1": credentialsContext,
  "https://w3id.org/vaccination/v1": vaccinationContext,
  "https://w3id.org/security/v3-unstable": securityV3Context, 
  "https://w3id.org/security/suites/ed25519-2020/v1": ed25519,
  "https://w3id.org/security/bbs/v1": bbs2020,
  "https://w3id.org/pathogen/v1": pathogen
};

export function addCache(keyPair) {
    const publicKey = {
        id: keyPair.id,
        controller: keyPair.controller,
        publicKeyBase58: keyPair.publicKeyBase58
    }

    const controller = {
      '@context': "https://w3id.org/security/v2",
        id: keyPair.controller,
        assertionMethod: [ keyPair.id ],
        authentication: [ keyPair.id ]
    }

    contexts[publicKey.id]  = publicKey;
    contexts[controller.id] = controller;
}

export const documentLoader = async url => {
  const context = contexts[url];

  if (context) {
    return {
      contextUrl: null,
      document: context,
      documentUrl: url,
    };
  }

  if(url && url.startsWith('did:')) {
    try {
      const document = await resolveDID(url);

      console.log(document);
      if (document.didResolutionMetadata.error) {
        console.log(document.didResolutionMetadata.error, document.didResolutionMetadata.message);
      }

      contexts[url] = document.didDocument;
      return {
        url,
        document: document.didDocument,
        static: true
      }
    } catch (err) {
      console.log(err);
    }
  }

  console.log("Unsupported URL on Tests", url);
};