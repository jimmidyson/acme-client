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

import io.fabric8.acme.client.model.NewRegistrationBuilder;
import io.fabric8.acme.client.model.Registration;
import okhttp3.HttpUrl;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.security.KeyPairGenerator;

import static io.fabric8.acme.client.Helpers.noncedResponse;
import static org.junit.Assert.assertEquals;

public class RegistrationTest extends BaseTest {

  @Test
  public void testNewRegistrationWithLinkRelations() throws Exception {
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
      .addHeader("Location", "https://acme-staging.api.letsencrypt.org/acme/reg/1")
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration().create(
      new NewRegistrationBuilder().addToContact("mailto", "noone@nowhere.com").build()
    );

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
  }

  @Test
  public void testNewRegistrationBuilderWithBodyRelations() throws Exception {
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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "  \"authorizations\": \"https://acme-staging.api.letsencrypt.org/acme/new-authz\",\n" +
      "  \"certificates\": \"https://acme-staging.api.letsencrypt.org/acme/certificates\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", "https://acme-staging.api.letsencrypt.org/acme/reg/1")
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration()
      .createNew().addToContact("mailto", "noone@nowhere.com")
      .send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/certificates", reg.getCertificatesLocation());
  }

  @Test
  public void testNewRegistrationBuilderAgreeToTerms() throws Exception {
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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"authorizations\": \"https://acme-staging.api.letsencrypt.org/acme/new-authz\",\n" +
      "  \"certificates\": \"https://acme-staging.api.letsencrypt.org/acme/certificates\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration()
      .createNew().addToContact("mailto", "noone@nowhere.com").withAgreeToTerms(true)
      .send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/certificates", reg.getCertificatesLocation());
    assertEquals(server.url("/acme/reg/1").toString(), reg.getLocation());
  }

  @Test
  public void testUpdateNewRegistrationContact() throws Exception {
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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"authorizations\": \"https://acme-staging.api.letsencrypt.org/acme/new-authz\",\n" +
      "  \"certificates\": \"https://acme-staging.api.letsencrypt.org/acme/certificates\"\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CREATED)
    );

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
      "  \"contact\": [\n" +
      "    \"mailto:someone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration()
      .edit().addToContact("mailto", "someone@nowhere.com")
      .send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/certificates", reg.getCertificatesLocation());
    assertEquals("someone@nowhere.com", reg.getContact().get("mailto"));
    assertEquals(server.url("/acme/reg/1").toString(), reg.getLocation());
  }

  @Test
  public void testUpdateExistingRegistrationContact() throws Exception {
    server.enqueue(noncedResponse(null)
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CONFLICT)
    );

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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    server.enqueue(noncedResponse("{\n" +
      "  \"id\": 1,\n" +
      "  \"key\": {\n" +
      "    \"kty\": \"RSA\",\n" +
      "    \"kid\": \"3gb1Haaaaaah0TBsQaaaaa\",\n" +
      "    \"n\": \"asafada-kLP-2mT3vBaWJG_JLJKdV5xtdsEOkmAZzY91fRM4HoLmvLrpjB4siACOZulkyKgs8DM0v9BP4T9hIqUBzvKLGRCCXFypwLDVyLYmkTsFwi-wvxfS13rZXdrLjwdAztLUIsJGqCZY6Lw6XZ1E9GriWnQQCqYRLi3ECEi33-BcuYJ7FBz36eeRZeGcHOLE5susgO00YxTAha4dgjl_SnbvYMOTXv4PEk7ai_ecQk-XlVGcCJrw\",\n" +
      "    \"e\": \"AQAB\"\n" +
      "  },\n" +
      "  \"contact\": [\n" +
      "    \"mailto:someone@nowhere.com\"\n" +
      "  ],\n" +
      "  \"initialIp\": \"86.11.222.69\",\n" +
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration()
      .edit().addToContact("mailto", "someone@nowhere.com")
      .send();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
    assertEquals("someone@nowhere.com", reg.getContact().get("mailto"));
    assertEquals(server.url("/acme/reg/1").toString(), reg.getLocation());
  }

  @Test
  public void testGetRegistrationWithKeyOnly() throws Exception {
    server.enqueue(noncedResponse(null)
      .addHeader("Location", server.url("/acme/reg/1"))
      .setResponseCode(HttpURLConnection.HTTP_CONFLICT)
    );

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
      "  \"createdAt\": \"2016-02-29T13:43:09.201427499Z\",\n" +
      "  \"agreement\": \"https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf\",\n" +
      "}")
      .addHeader("Link", "<https://acme-staging.api.letsencrypt.org/acme/new-authz>;rel=\"next\"")
      .addHeader("Link", "<https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf>;rel=\"terms-of-service\"")
      .setResponseCode(HttpURLConnection.HTTP_ACCEPTED)
    );

    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());

    Registration reg = client.registration().get();

    assertEquals("https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf", reg.getAgreementLocation());
    assertEquals("https://acme-staging.api.letsencrypt.org/acme/new-authz", reg.getAuthorizationsLocation());
    assertEquals(server.url("/acme/reg/1").toString(), reg.getLocation());
  }

}
