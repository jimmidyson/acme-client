package io.fabric8.acme.client.model;

public abstract class Challenge {

  private String type;

  protected Challenge(String type) {
    this.type = type;
  }

  public String getType() {
    return type;
  }
}
