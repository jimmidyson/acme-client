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

import net.minidev.json.JSONObject;

public class Dns01Challenge extends ChallengeWithToken {

  public Dns01Challenge(String token, Status status, String uri) {
    super(token, "dns-01", status, uri);
  }

  public Dns01Challenge(String token, Status status, String uri, String keyAuthorization) {
    super(token, "dns-01", status, uri, keyAuthorization);
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("type", getType());
    jsonObject.put("token", getToken());
    return jsonObject;
  }
}
