package io.fabric8.acme.client;

import okhttp3.mockwebserver.MockWebServer;

public class Helpers {

  private Helpers() {
  }

  public static String newDirectory(MockWebServer server) {
    return "{" +
      "\"new-reg\": \"" + server.url("/acme/new-reg") + "\"," +
      "\"recover-reg\": \"" + server.url("/acme/recover-reg") + "\"," +
      "\"new-authz\": \"" + server.url("/acme/new-authz") + "\"," +
      "\"new-cert\": \"" + server.url("/acme/new-cert") + "\"," +
      "\"revoke-cert\": \"" + server.url("/acme/revoke-cert") + "\"" +
      "}";
  }
}
