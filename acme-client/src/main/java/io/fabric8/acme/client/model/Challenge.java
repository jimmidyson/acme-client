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
    String keyAuthorization = (String) jsonObject.get("keyAuthorization");
    switch (type) {
      case "dns-01":
        return new Dns01Challenge((String) jsonObject.get("token"), status, uri, keyAuthorization);
      case "http-01":
        return new Http01Challenge((String) jsonObject.get("token"), status, uri, keyAuthorization);
      case "tls-sni-01":
        return new TlsSni01Challenge((String) jsonObject.get("token"), status, uri, keyAuthorization);
      default:
        throw new ACMEClientException("unknownChallengeType", "Unknown challenge type: " + type);
    }
  }

  public abstract JSONObject toJSONObject();
}
