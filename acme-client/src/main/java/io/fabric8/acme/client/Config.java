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
package io.fabric8.acme.client;

import com.nimbusds.jose.JWSAlgorithm;
import io.sundr.builder.annotations.Buildable;

import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder"
)
public class Config {

  private URL server;

  private KeyPair keyPair;

  private String[] pins;

  private JWSAlgorithm jwsAlgorithm;

  public Config(URL server, KeyPair keyPair, JWSAlgorithm jwsAlgorithm, String... pins) {
    if (server == null) {
      throw new ACMEClientException("configError", "Server is required");
    }
    this.server = server;

    if (keyPair == null) {
      throw new ACMEClientException("configError", "Account key pair is required");
    }
    this.keyPair = keyPair;

    if (jwsAlgorithm != null) {
      this.jwsAlgorithm = jwsAlgorithm;
    } else {
      if (this.keyPair.getPrivate() instanceof RSAPrivateKey) {
        this.jwsAlgorithm = JWSAlgorithm.RS256;
      } else {
        this.jwsAlgorithm = JWSAlgorithm.ES256;
      }
    }

    this.pins = pins;
  }

  public URL getServer() {
    return server;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public String[] getPins() {
    return pins;
  }

  public JWSAlgorithm getJwsAlgorithm() {
    return jwsAlgorithm;
  }
}
