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

import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.internal.JWKUtils;
import io.fabric8.acme.client.model.Registration;
import okhttp3.HttpUrl;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import static io.fabric8.acme.client.Helpers.newDirectory;
import static io.fabric8.acme.client.Helpers.noncedResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RegistrationRecoveryTest extends BaseTest {

  @Test
  public void testRecovery() throws Exception {
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

    server.enqueue(noncedResponse(newDirectory(server)));

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + newJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:someonene@nowhere.com\"\n" +
      "  ],\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
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
      .addHeader("Retry-After", "1")
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
      .addHeader("Retry-After", DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now().plus(1, ChronoUnit.SECONDS)))
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
      .setResponseCode(HttpURLConnection.HTTP_OK)
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

    client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(newKeyPair)
        .build());

    reg = client.registration().recovery().withBase(reg.getLocation()).addToContact("mailto", "someone@nowhere.com").send();
    assertNotNull(reg);

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/recover-reg", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
  }



  @Test(expected = ACMEClientException.class)
  public void testRecoveryFailure() throws Exception {
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

    server.enqueue(noncedResponse(newDirectory(server)));

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": " + newJWK.toJSONString() + ",\n" +
      "  \"contact\": [\n" +
      "    \"mailto:someonene@nowhere.com\"\n" +
      "  ],\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
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
      .addHeader("Retry-After", "1")
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
      .addHeader("Retry-After", DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now().plus(1, ChronoUnit.SECONDS)))
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
      .setResponseCode(HttpURLConnection.HTTP_NOT_FOUND)
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

    client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(newKeyPair)
        .build());

    client.registration().recovery().withBase(reg.getLocation()).addToContact("mailto", "someone@nowhere.com").send();

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/recover-reg", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
    assertEquals("/acme/reg/1", server.takeRequest().getPath());
  }

}
