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

import okhttp3.mockwebserver.MockWebServer;
import org.junit.rules.ExternalResource;

import java.io.IOException;

import static io.fabric8.acme.client.Helpers.newDirectory;
import static io.fabric8.acme.client.Helpers.noncedResponse;

public class MockServerRule extends ExternalResource {

  private MockWebServer server = new MockWebServer();

  @Override
  protected void before() throws Throwable {
    server.start();

    server.enqueue(noncedResponse(newDirectory(server)));

  }

  @Override
  protected void after() {
    try {
      server.shutdown();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public MockWebServer getServer() {
    return server;
  }
}
