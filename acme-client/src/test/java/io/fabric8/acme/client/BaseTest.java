package io.fabric8.acme.client;

import okhttp3.mockwebserver.MockWebServer;
import org.junit.Rule;

public abstract class BaseTest {

  @Rule
  public MockServerRule serverRule = new MockServerRule();

  protected MockWebServer server = serverRule.getServer();

}
