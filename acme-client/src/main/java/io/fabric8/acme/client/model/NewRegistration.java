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
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.Map;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false,
  inline = @Inline(prefix = "Sendable", value = "send", type = Sendable.class, returnType = Registration.class)
)
public class NewRegistration extends BaseResource {

  private Map<String, String> contact;

  private boolean agreeToTerms;

  public NewRegistration(Map<String, String> contact, boolean agreeToTerms) {
    super(Resource.ResourceType.NEW_REGISTRATION);
    this.contact = contact;
    this.agreeToTerms = agreeToTerms;
  }

  public Map<String, String> getContact() {
    return contact;
  }

  public boolean isAgreeToTerms() {
    return agreeToTerms;
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject json = new JSONObject();
    json.put("resource", getType().type());
    if (contact != null && !contact.isEmpty()) {
      JSONArray contacts = new JSONArray();
      for (Map.Entry<String, String> contact : getContact().entrySet()) {
        contacts.add(contact.getKey() + ":" + contact.getValue());
      }
      json.put("contact", contacts);
    }
    return json;
  }
}
