package io.fabric8.acme.client.model;

public class TlsSni01Challenge extends Challenge {

  private String token;

  public TlsSni01Challenge(String token) {
    super("tls-sni-01");
    this.token = token;
  }

  public String getToken() {
    return token;
  }
}
