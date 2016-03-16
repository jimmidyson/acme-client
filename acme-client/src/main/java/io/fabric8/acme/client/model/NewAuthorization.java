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

import io.fabric8.acme.client.dsl.Sendable;
import io.sundr.builder.annotations.Buildable;
import io.sundr.builder.annotations.Inline;
import net.minidev.json.JSONObject;

import java.util.Map;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false,
  inline = @Inline(prefix = "Sendable", value = "send", type = Sendable.class, returnType = Authorization.class)
)
public class NewAuthorization extends BaseResource {

  private Map<String, String> identifier;

  public NewAuthorization(Map<String, String> identifier) {
    super(ResourceType.NEW_AUTHORIZATION);
    this.identifier = identifier;
  }

  public Map<String, String> getIdentifier() {
    return identifier;
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject json = new JSONObject();
    json.put("resource", getType().type());
    if (identifier != null && !identifier.isEmpty()) {
      JSONObject identifiers = new JSONObject();
      for (Map.Entry<String, String> identifier : getIdentifier().entrySet()) {
        identifiers.put(identifier.getKey(), identifier.getValue());
      }
      json.put("identifier", identifiers);
    }
    return json;
  }
}
