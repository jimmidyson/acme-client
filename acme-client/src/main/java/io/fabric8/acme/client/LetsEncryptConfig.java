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

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder"
)
public class LetsEncryptConfig extends Config {

  public static final URL LETSENCRYPT_PRODUCTION_URL = letsEncryptProdURL();

  private static URL letsEncryptProdURL() {
    URL u = null;
    try {
      u = new URL("https://acme-v01.api.letsencrypt.org/directory");
    } catch (MalformedURLException e) {
      // Should never be reached
    }
    return u;
  }

  public LetsEncryptConfig(KeyPair keyPair, JWSAlgorithm jwsAlgorithm, String... pins) {
    super(LETSENCRYPT_PRODUCTION_URL, keyPair, jwsAlgorithm, "sha1/hQCy8MqhiC5J3y6wM7kyK2RHk1g=");
  }

}
