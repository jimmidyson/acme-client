package io.fabric8.acme.client.model;

import net.minidev.json.JSONObject;

public class Http01Challenge extends Challenge {

  private String token;

  public Http01Challenge(String token, Status status, String uri) {
    super("http-01", status, uri);
    this.token = token;
  }

  public String getToken() {
    return token;
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("type", getType());
    jsonObject.put("token", token);
    return jsonObject;
  }
}
