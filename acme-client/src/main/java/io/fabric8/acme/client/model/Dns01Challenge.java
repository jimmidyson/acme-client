package io.fabric8.acme.client.model;

public class Dns01Challenge extends Challenge {

  private String token;

  public Dns01Challenge(String token) {
    super("dns-01");
    this.token = token;
  }

  public String getToken() {
    return token;
  }
}
