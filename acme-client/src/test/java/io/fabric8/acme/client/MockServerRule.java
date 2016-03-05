package io.fabric8.acme.client;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.rules.ExternalResource;

import java.io.IOException;

import static io.fabric8.acme.client.Helpers.newDirectory;

public class MockServerRule extends ExternalResource {

  private MockWebServer server = new MockWebServer();

  @Override
  protected void before() throws Throwable {
    server.start();

    server.enqueue(new MockResponse().setBody(newDirectory(server))
      .addHeader("Replay-Nonce", "aaa"));

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
