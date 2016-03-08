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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.dsl.GetCreateUpdateEditKeyUpdatable;
import io.fabric8.acme.client.internal.HttpClientUtils;
import io.fabric8.acme.client.internal.JWKUtils;
import io.fabric8.acme.client.internal.Nonce;
import io.fabric8.acme.client.internal.RegistrationOperations;
import io.fabric8.acme.client.internal.Signer;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.InlineNewRegistration;
import io.fabric8.acme.client.model.InlineRegistration;
import io.fabric8.acme.client.model.NewRegistration;
import io.fabric8.acme.client.model.Registration;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.util.Map;

public class DefaultACMEClient implements ACMEClient {

  private JSONParser jsonParser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);

  private OkHttpClient okHttpClient;

  private Config config;

  private Directory directory;

  private Signer signer;

  private JWK jwk;

  private Nonce nonce;

  public DefaultACMEClient(String server, KeyPair keyPair) throws MalformedURLException {
    this(new ConfigBuilder().withServer(new URL(server)).withKeyPair(keyPair).build());
  }

  public DefaultACMEClient(Config config) {
    this.config = config;

    // Configure the HTTP client.
    okHttpClient = HttpClientUtils.newClient(config);

    try {
      // Configure the signer.
      signer = new Signer(config.getKeyPair().getPrivate());

      // Get the JWK.
      jwk = JWKUtils.jwkFromPublicKey(config.getKeyPair().getPublic());

      // Set up the nonce holder/extractor
      nonce = new Nonce(okHttpClient, config.getServer());

      // Validate this is an ACME server by retrieving the directory -
      // see https://ietf-wg-acme.github.io/acme/#rfc.section.6.2.
      Request request = new Request.Builder()
        .url(config.getServer())
        .build();

      Response response = okHttpClient.newCall(request).execute();

      if (!response.isSuccessful()) {
        throw new ACMEClientException(response.code(), response.message(), response.body().string());
      }

      try (InputStream body = response.body().byteStream()) {
        Map<String, String> directoryResponse = (Map<String, String>) jsonParser.parse(body);
        this.directory = new Directory(directoryResponse);
      }

      nonce.extractNonce(response);

    } catch (IOException | ParseException | JOSEException e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  @Override
  public Directory directory() {
    return directory;
  }

  @Override
  public GetCreateUpdateEditKeyUpdatable<Registration, NewRegistration, InlineNewRegistration, InlineRegistration> registration() {
    return new RegistrationOperations(directory, okHttpClient, nonce, config.getJwsAlgorithm(), signer, jwk);
  }

}
