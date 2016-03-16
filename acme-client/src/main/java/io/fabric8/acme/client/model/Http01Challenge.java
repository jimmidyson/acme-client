package io.fabric8.acme.client.model;

public class Http01Challenge extends Challenge {

  private String token;

  public Http01Challenge(String token) {
    super("http-01");
    this.token = token;
  }

  public String getToken() {
    return token;
  }
}
