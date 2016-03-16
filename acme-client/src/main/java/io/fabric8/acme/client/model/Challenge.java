package io.fabric8.acme.client.model;

import io.fabric8.acme.client.ACMEClientException;
import net.minidev.json.JSONObject;

public abstract class Challenge {

  private String type;

  private Status status;

  private String uri;

  protected Challenge(String type, Status status, String uri) {
    this.type = type;
    this.status = status;
    this.uri = uri;
  }

  public String getType() {
    return type;
  }

  public String getUri() {
    return uri;
  }

  public Status getStatus() {
    return status;
  }

  public static Challenge fromJSONObject(JSONObject jsonObject) {
    Status status = Status.findByStatus((String) jsonObject.get("status"));
    String uri = (String) jsonObject.get("uri");
    String type = (String) jsonObject.get("type");
    switch (type) {
      case "dns-01":
        return new Dns01Challenge((String) jsonObject.get("token"), status, uri);
      case "http-01":
        return new Http01Challenge((String) jsonObject.get("token"), status, uri);
      case "tls-sni-01":
        return new TlsSni01Challenge((String) jsonObject.get("token"), status, uri);
      default:
        throw new ACMEClientException("unknownChallengeType", "Unknown challenge type: " + type);
    }
  }

  public abstract JSONObject toJSONObject();
}
