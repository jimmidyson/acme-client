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
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.List;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false
)
public class Authorization extends BaseResource {

  private Identifier identifier;

  private Status status = Status.PENDING;

  private TemporalAccessor expires;

  private List<Challenge> challenges;

  private List<List<Challenge>> combinations;

  public Authorization(Identifier identifier, TemporalAccessor expires, List<Challenge> challenges, List<List<Challenge>> combinations) {
    super(ResourceType.AUTHORIZATION);
    this.identifier = identifier;
    this.expires = expires;
    this.challenges = challenges;
    this.combinations = combinations;
  }

  public Identifier getIdentifier() {
    return identifier;
  }

  public Status getStatus() {
    return status;
  }

  public TemporalAccessor getExpires() {
    return expires;
  }

  public List<Challenge> getChallenges() {
    return challenges;
  }

  public List<List<Challenge>> getCombinations() {
    return combinations;
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject jsonObject = new JSONObject();

    jsonObject.put("identifier", identifier);
    jsonObject.put("status", status.status());

    if (expires != null) {
      jsonObject.put("expires", DateTimeFormatter.ISO_INSTANT.format(expires));
    }

    if (challenges != null && !challenges.isEmpty()) {
      JSONArray jsonChallenges = new JSONArray();
      for (Challenge challenge : challenges) {
        jsonChallenges.add(challenge.toJSONObject());
      }
      jsonObject.put("challenges", jsonChallenges);
    }

    if (combinations != null && !combinations.isEmpty()) {
      JSONArray jsonCombinations = new JSONArray();

      for (List<Challenge> combination : combinations) {
        JSONArray jsonCombination = new JSONArray();

        for (Challenge challenge : combination) {
          jsonCombination.add(challenges.indexOf(challenge));
        }

        jsonCombinations.add(jsonCombination);
      }

      jsonObject.put("combinations", jsonCombinations);
    }

    return jsonObject;
  }

  public static Authorization fromJSONObject(JSONObject jsonObject) {
    AuthorizationBuilder builder = new AuthorizationBuilder();

    builder.withIdentifier(Identifier.fromJSONObject((JSONObject) jsonObject.get("identifier")));

    String status = (String) jsonObject.get("status");
    if (status != null && !status.isEmpty()) {
      builder.withStatus(Status.findByStatus(status));
    }

    String expires = (String) jsonObject.get("expires");
    if (expires != null && !expires.isEmpty()) {
      builder.withExpires(Instant.parse(expires));
    }

    JSONArray challenges = (JSONArray) jsonObject.get("challenges");
    for (Object challenge : challenges) {
      builder.addToChallenges(Challenge.fromJSONObject((JSONObject) challenge));
    }

    JSONArray combinations = (JSONArray) jsonObject.get("combinations");
    if (combinations != null && !combinations.isEmpty()) {
      for (Object combinationArray : combinations) {
        JSONArray combination = (JSONArray) combinationArray;
        List<Challenge> comboList = new ArrayList<>(combination.size());

        for (Object challengeIndex : combination) {
          comboList.add(builder.getChallenges().get(((Long) challengeIndex).intValue()));
        }

        builder.addToCombinations(comboList);
      }
    }

    return builder.build();
  }

}
