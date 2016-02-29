/**
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.fabric8.acme.client.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import io.fabric8.acme.client.ACMEClientException;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class Signer {

  private JWSSigner signer;

  public Signer(PrivateKey privateKey) {
    if (privateKey == null) {
      throw new ACMEClientException("signingError", "Account private key pair is required for signing");
    }

    if (privateKey instanceof RSAPrivateKey) {
      signer = new RSASSASigner((RSAPrivateKey) privateKey);
    } else if (privateKey instanceof ECPrivateKey) {
      try {
        signer = new ECDSASigner((ECPrivateKey) privateKey);
      } catch (JOSEException e) {
        throw ACMEClientException.launderThrowable(e);
      }
    }
  }

  public void sign(JWSObject jwsObject) {
    try {
      jwsObject.sign(signer);
    } catch (JOSEException e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

}
