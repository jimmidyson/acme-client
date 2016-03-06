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
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;

import java.security.KeyPairGenerator;

import static org.junit.Assert.assertEquals;

public class DiscoveryTest extends BaseTest {
  @Test
  public void testSuccessfulDiscovery() throws Exception {
    HttpUrl baseUrl = server.url("/directory");

    ACMEClient client = new DefaultACMEClient(
      new ConfigBuilder()
        .withServer(baseUrl.url())
        .withKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        .build());
    Directory dir = client.directory();
    assertEquals(server.url("/acme/new-reg").toString(), dir.newReg());
    assertEquals(server.url("/acme/recover-reg").toString(), dir.recoverReg());
    assertEquals(server.url("/acme/new-authz").toString(), dir.newAuthz());
    assertEquals(server.url("/acme/new-cert").toString(), dir.newCert());
    assertEquals(server.url("/acme/revoke-cert").toString(), dir.revokeCert());

    RecordedRequest request1 = server.takeRequest();
    assertEquals("/directory", request1.getPath());
  }
}
