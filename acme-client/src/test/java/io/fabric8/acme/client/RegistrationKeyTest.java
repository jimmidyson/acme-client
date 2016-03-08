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

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import io.fabric8.acme.client.internal.JWKUtils;
import io.fabric8.acme.client.model.Registration;
import net.minidev.json.JSONObject;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import static io.fabric8.acme.client.Helpers.newDirectory;
import static io.fabric8.acme.client.Helpers.noncedResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RegistrationKeyTest extends BaseTest {

  @Test
  public void testKeyUpdate() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair oldKeyPair = kpg.generateKeyPair();
    KeyPair newKeyPair = kpg.generateKeyPair();
    JWK oldJWK = JWKUtils.jwkFromPublicKey(oldKeyPair.getPublic());
    JWK newJWK = JWKUtils.jwkFromPublicKey(newKeyPair.getPublic());

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + oldJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:noone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

    server.enqueue(noncedResponse(null)
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CONFLICT)
    );

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + oldJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:noone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + newJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:noone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    server.enqueue(noncedResponse(newDirectory(server)));

    server.enqueue(noncedResponse(null)
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CONFLICT)
    );

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + newJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:noone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(oldKeyPair)
        .build());

    Registration reg = client.registration().createNew().addToContact("mailto", "noone@nowhere.com").send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());

    client.registration().updateKey(newKeyPair);

    client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(newKeyPair)
        .build());

    reg = client.registration().get();
    assertEquals("noone@nowhere.com", reg.getContact().get("mailto"));

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());

    // This is the one we want to validate
    // Follow https://ietf-wg-acme.github.io/acme/#account-key-roll-over
    //


    RecordedRequest request = server.takeRequest();
    assertEquals("/acme/reg/1", request.getPath());
    String requestBody = request.getBody().readUtf8();
    JWSObject jws = JWSObject.parse(requestBody);
    assertTrue(jws.verify(new RSASSAVerifier((RSAPublicKey) oldKeyPair.getPublic())));
    assertEquals(oldJWK.computeThumbprint(), jws.getHeader().getJWK().computeThumbprint());
    JSONObject payload = jws.getPayload().toJSONObject();
    // 1. Check that the contents of the “newKey” attribute are a valid JWS
    JWSObject newKeyJWS = JWSObject.parse((String) payload.get("newKey"));
    // 2. Check that the “newKey” JWS verifies using the key in the “jwk” header parameter of the JWS
    assertTrue(newKeyJWS.verify(new RSASSAVerifier((RSAKey) newKeyJWS.getHeader().getJWK())));
    // 3. Check that the payload of the JWS is a valid JSON object
    JSONObject newKeyPayload = newKeyJWS.getPayload().toJSONObject();
    assertNotNull(newKeyPayload);
    // 4. Check that the “resource” field of the object has the value “reg”
    assertEquals("reg", newKeyPayload.get("resource"));
    // 5. Check that the “oldKey” field of the object contains the JWK thumbprint of the account key for this registration
    assertEquals(oldJWK.computeThumbprint(), new Base64URL((String) newKeyPayload.get("oldKey")));

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
  }

}
