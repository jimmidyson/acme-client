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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.fabric8.acme.client.internal.JWKUtils;
import io.fabric8.acme.client.model.Authorization;
import io.fabric8.acme.client.model.Challenge;
import io.fabric8.acme.client.model.Registration;
import net.minidev.json.JSONObject;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static io.fabric8.acme.client.Helpers.noncedResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AuthorizationTest extends BaseTest {

  @Test
  public void testNewAuthorization() throws Exception {
    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
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

    server.enqueue(
      noncedResponse("{\"identifier\":{\"type\":\"dns\",\"value\":\"fabric8.io\"},\"status\":\"pending\",\"expires\":\"2017-03-23T21:06:45.899078471Z\",\"challenges\":[{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"},{\"type\":\"tls-sni-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/zxcvb/98765") + "\",\"token\":\"asdfg\"},{\"type\":\"http-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/lkjhg/456321") + "\",\"token\":\"mnbvc\"}],\"combinations\":[[0],[1,2]]}")
        .addHeader("Location", server.url("/acme/authorization/111"))
        .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration().createNew().send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());

    Authorization authz = client.authorization().createNew().withNewIdentifier("dns", "fabric8.io").send();
    assertNotNull(authz);
    assertEquals(server.url("/acme/authorization/111").toString(), authz.getLocation());

    assertEquals(3, authz.getChallenges().size());
    assertEquals("dns-01", authz.getChallenges().get(0).getType());
    assertEquals("tls-sni-01", authz.getChallenges().get(1).getType());
    assertEquals("http-01", authz.getChallenges().get(2).getType());

    assertEquals(2, authz.getCombinations().size());
    assertEquals(2, authz.getCombinations().get(1).size());
    assertEquals(authz.getChallenges().get(0), authz.getCombinations().get(0).get(0));
    assertEquals(authz.getChallenges().get(1), authz.getCombinations().get(1).get(0));
    assertEquals(authz.getChallenges().get(2), authz.getCombinations().get(1).get(1));
  }

  @Test
  public void testLocateAuthorization() throws Exception {
    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
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

    server.enqueue(
      noncedResponse("{\"identifier\":{\"type\":\"dns\",\"value\":\"fabric8.io\"},\"status\":\"pending\",\"expires\":\"2017-03-23T21:06:45.899078471Z\",\"challenges\":[{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"},{\"type\":\"tls-sni-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/zxcvb/98765") + "\",\"token\":\"asdfg\"},{\"type\":\"http-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/lkjhg/456321") + "\",\"token\":\"mnbvc\"}],\"combinations\":[[0],[1,2]]}")
        .addHeader("Location", server.url("/acme/authorization/111"))
        .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );
    server.enqueue(
      noncedResponse("{\"identifier\":{\"type\":\"dns\",\"value\":\"fabric8.io\"},\"status\":\"pending\",\"expires\":\"2017-03-23T21:06:45.899078471Z\",\"challenges\":[{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"},{\"type\":\"tls-sni-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/zxcvb/98765") + "\",\"token\":\"asdfg\"},{\"type\":\"http-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/lkjhg/456321") + "\",\"token\":\"mnbvc\"}],\"combinations\":[[0],[1,2]]}")
        .setResponseCode(HttpURLConnection.HTTP_OK)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration().createNew().send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());

    Authorization authz = client.authorization().createNew().withNewIdentifier("dns", "fabric8.io").send();
    assertNotNull(authz);
    assertEquals(server.url("/acme/authorization/111").toString(), authz.getLocation());

    authz = client.authorization().at(authz.getLocation()).get();
    assertNotNull(authz);

    assertEquals(3, authz.getChallenges().size());
    assertEquals("dns-01", authz.getChallenges().get(0).getType());
    assertEquals("tls-sni-01", authz.getChallenges().get(1).getType());
    assertEquals("http-01", authz.getChallenges().get(2).getType());

    assertEquals(2, authz.getCombinations().size());
    assertEquals(2, authz.getCombinations().get(1).size());
    assertEquals(authz.getChallenges().get(0), authz.getCombinations().get(0).get(0));
    assertEquals(authz.getChallenges().get(1), authz.getCombinations().get(1).get(0));
    assertEquals(authz.getChallenges().get(2), authz.getCombinations().get(1).get(1));
  }

  @Test
  public void testReadyChallenge() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair keyPair = kpg.generateKeyPair();
    JWK jwk = JWKUtils.jwkFromPublicKey(keyPair.getPublic());
    Base64URL jwkThumb = jwk.computeThumbprint();

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
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

    server.enqueue(
      noncedResponse("{\"identifier\":{\"type\":\"dns\",\"value\":\"fabric8.io\"},\"status\":\"pending\",\"expires\":\"2017-03-23T21:06:45.899078471Z\",\"challenges\":[{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"},{\"type\":\"tls-sni-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/zxcvb/98765") + "\",\"token\":\"asdfg\"},{\"type\":\"http-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/lkjhg/456321") + "\",\"token\":\"mnbvc\"}],\"combinations\":[[0],[1,2]]}")
        .addHeader("Location", server.url("/acme/authorization/111"))
        .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );
    server.enqueue(
      noncedResponse("{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\",\"keyAuthorization\":\"qwerty." + jwkThumb.toString() + "\"}")
        .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(keyPair)
        .build());

    Registration reg = client.registration().createNew().send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());

    Authorization authz = client.authorization().createNew().withNewIdentifier("dns", "fabric8.io").send();
    assertNotNull(authz);
    assertEquals("/acme/new-authz", server.takeRequest().getPath());

    assertEquals(server.url("/acme/authorization/111").toString(), authz.getLocation());
    assertEquals(3, authz.getChallenges().size());
    assertEquals("dns-01", authz.getChallenges().get(0).getType());
    assertEquals("tls-sni-01", authz.getChallenges().get(1).getType());
    assertEquals("http-01", authz.getChallenges().get(2).getType());

    assertEquals(2, authz.getCombinations().size());
    assertEquals(2, authz.getCombinations().get(1).size());
    assertEquals(authz.getChallenges().get(0), authz.getCombinations().get(0).get(0));
    assertEquals(authz.getChallenges().get(1), authz.getCombinations().get(1).get(0));
    assertEquals(authz.getChallenges().get(2), authz.getCombinations().get(1).get(1));

    Challenge challenge = client.challenges().use(authz.getCombinations().get(0).get(0)).ready();
    assertNotNull(challenge);
    assertEquals(server.url("/acme/challenge/abcde/1234").toString(), challenge.getUri());

    RecordedRequest request = server.takeRequest();
    assertEquals("/acme/challenge/abcde/1234", request.getPath());
    String requestBody = request.getBody().readUtf8();
    JWSObject jws = JWSObject.parse(requestBody);
    JSONObject payload = jws.getPayload().toJSONObject();
    assertEquals("qwerty." + jwkThumb.toString(), payload.get("keyAuthorization"));
  }



  @Test
  public void testReadyAtChallenge() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair keyPair = kpg.generateKeyPair();
    JWK jwk = JWKUtils.jwkFromPublicKey(keyPair.getPublic());
    Base64URL jwkThumb = jwk.computeThumbprint();

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
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

    server.enqueue(
      noncedResponse("{\"identifier\":{\"type\":\"dns\",\"value\":\"fabric8.io\"},\"status\":\"pending\",\"expires\":\"2017-03-23T21:06:45.899078471Z\",\"challenges\":[{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"},{\"type\":\"tls-sni-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/zxcvb/98765") + "\",\"token\":\"asdfg\"},{\"type\":\"http-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/lkjhg/456321") + "\",\"token\":\"mnbvc\"}],\"combinations\":[[0],[1,2]]}")
        .addHeader("Location", server.url("/acme/authorization/111"))
        .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );
    server.enqueue(
      noncedResponse("{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\"}")
        .setResponseCode(HttpURLConnection.HTTP_OK)
    );
    server.enqueue(
      noncedResponse("{\"type\":\"dns-01\",\"status\":\"pending\",\"uri\":\"" + server.url("/acme/challenge/abcde/1234") + "\",\"token\":\"qwerty\",\"keyAuthorization\":\"qwerty." + jwkThumb.toString() + "\"}")
        .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(keyPair)
        .build());

    Registration reg = client.registration().createNew().send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());

    assertEquals("/directory", server.takeRequest().getPath());
    assertEquals("/acme/new-reg", server.takeRequest().getPath());

    Authorization authz = client.authorization().createNew().withNewIdentifier("dns", "fabric8.io").send();
    assertNotNull(authz);
    assertEquals("/acme/new-authz", server.takeRequest().getPath());

    assertEquals(server.url("/acme/authorization/111").toString(), authz.getLocation());
    assertEquals(3, authz.getChallenges().size());
    assertEquals("dns-01", authz.getChallenges().get(0).getType());
    assertEquals("tls-sni-01", authz.getChallenges().get(1).getType());
    assertEquals("http-01", authz.getChallenges().get(2).getType());

    assertEquals(2, authz.getCombinations().size());
    assertEquals(2, authz.getCombinations().get(1).size());
    assertEquals(authz.getChallenges().get(0), authz.getCombinations().get(0).get(0));
    assertEquals(authz.getChallenges().get(1), authz.getCombinations().get(1).get(0));
    assertEquals(authz.getChallenges().get(2), authz.getCombinations().get(1).get(1));

    Challenge challenge = client.challenges().at(authz.getCombinations().get(0).get(0).getUri()).ready();
    assertNotNull(challenge);
    assertEquals(server.url("/acme/challenge/abcde/1234").toString(), challenge.getUri());

    assertEquals("/acme/challenge/abcde/1234", server.takeRequest().getPath());
    RecordedRequest request = server.takeRequest();
    assertEquals("/acme/challenge/abcde/1234", request.getPath());
    String requestBody = request.getBody().readUtf8();
    JWSObject jws = JWSObject.parse(requestBody);
    JSONObject payload = jws.getPayload().toJSONObject();
    assertEquals("qwerty." + jwkThumb.toString(), payload.get("keyAuthorization"));
  }

}
