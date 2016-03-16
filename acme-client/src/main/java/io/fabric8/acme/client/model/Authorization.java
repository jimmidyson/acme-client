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

import java.time.temporal.TemporalAccessor;
import java.util.List;
import java.util.Map;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false
)
public class Authorization extends BaseResource {

  public enum Status {
    UNKNOWN("unknown"),
    PENDING("pending"),
    PROCESSING("processing"),
    VALID("valid"),
    INVALID("invalid"),
    REVOKED("revoked");

    private String status;

    Status(String status) {
      this.status = status;
    }

    public String status() {
      return status;
    }

    static Status findByStatus(String status){
      for(Status v : values()){
        if( v.status.equals(status)){
          return v;
        }
      }
      return null;
    }
  }

  public Authorization() {
    super(ResourceType.AUTHORIZATION);
  }

  private Map<String, String> identifier;

  private Status status = Status.PENDING;

  private TemporalAccessor expires;

  private List<Challenge> challenges;

  private List<List<Integer>> combinations;

  @Override
  public JSONObject toJSONObject() {
    JSONObject json = new JSONObject();

    return json;
  }

  public static Authorization fromJSONObject(JSONObject jsonObject) {
    AuthorizationBuilder builder = new AuthorizationBuilder();

    return builder.build();
  }
}
