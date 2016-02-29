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

public interface Resource {

  enum ResourceType {
    NEW_REGISTRATION("new-reg"),
    RECOVER_REGISTRATION("recover-reg"),
    NEW_AUTHORIZATION("new-authz"),
    NEW_CERTIFICATE("new-cert"),
    REVOKE_CERTIFICATE("revoke-cert"),
    REGISTRATION("reg"),
    AUTHORIZATION("authz"),
    CHALLENGE("challenge"),
    CERTIFICATE("cert");

    private String type;

    ResourceType(String type) {
      this.type = type;
    }

    public String type() {
      return type;
    }

    static ResourceType findByType(String type){
      for(ResourceType v : values()){
        if( v.type.equals(type)){
          return v;
        }
      }
      return null;
    }
  }

  ResourceType getType();

  JSONObject toJSONObject();
}
