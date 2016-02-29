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

import io.fabric8.acme.client.model.Directory;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;

import java.security.KeyPairGenerator;

import static org.junit.Assert.assertEquals;

public class DiscoveryTest {

  @Test
  public void testSuccessfulDiscovery() throws Exception {
    MockWebServer server = new MockWebServer();
    try {
      server.enqueue(new MockResponse().setBody("{" +
        "\"new-reg\": \"https://example.com/acme/new-reg\"," +
        "\"recover-reg\": \"https://example.com/acme/recover-reg\"," +
        "\"new-authz\": \"https://example.com/acme/new-authz\"," +
        "\"new-cert\": \"https://example.com/acme/new-cert\"," +
        "\"revoke-cert\": \"https://example.com/acme/revoke-cert\"" +
      "}").addHeader("Replay-Nonce", "zv7LZB34F9OEusBNBo_enxjzLXzhcZ3B2x89gfHqKlA"));

      // Start the server.
      server.start();

      HttpUrl baseUrl = server.url("/directory");

      ACMEClient client = new DefaultACMEClient(
        new ConfigBuilder()
          .withServer(baseUrl.url())
          .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
          .build());
      Directory dir = client.directory();
      assertEquals("https://example.com/acme/new-reg", dir.newReg());
      assertEquals("https://example.com/acme/recover-reg", dir.recoverReg());
      assertEquals("https://example.com/acme/new-authz", dir.newAuthz());
      assertEquals("https://example.com/acme/new-cert", dir.newCert());
      assertEquals("https://example.com/acme/revoke-cert", dir.revokeCert());

      RecordedRequest request1 = server.takeRequest();
      assertEquals("/directory", request1.getPath());
    } finally {
      server.shutdown();
    }
  }
}
