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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class JWKUtils {

  private JWKUtils() {
  }

  public static JWK jwkFromPublicKey(PublicKey pub) throws JOSEException {
    if (pub instanceof RSAPublicKey) {
      RSAPublicKey publicKey = (RSAPublicKey) pub;
      return new RSAKey.Builder(publicKey)
        .keyIDFromThumbprint()
        .build();
    } else {
      ECPublicKey publicKey = (ECPublicKey) pub;
      return new ECKey.Builder(ECKey.Curve.forECParameterSpec(publicKey.getParams()), publicKey)
        .keyIDFromThumbprint()
        .build();
    }
  }

}
