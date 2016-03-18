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

import io.sundr.builder.annotations.Buildable;
import net.minidev.json.JSONObject;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false
)
public class Identifier {

  private String type;

  private String value;

  public Identifier(String type, String value) {
    this.type = type;
    this.value = value;
  }

  public String getType() {
    return type;
  }

  public String getValue() {
    return value;
  }

  public JSONObject toJSONObject() {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("type", type);
    jsonObject.put("value", value);
    return jsonObject;
  }

  public static Identifier fromJSONObject(JSONObject jsonObject) {
    if (jsonObject == null) {
      return null;
    }

    return new Identifier((String) jsonObject.get("type"), (String) jsonObject.get("value"));
  }
}
