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

import java.util.Map;
import java.util.stream.Collectors;

public class Directory {

  private Map<Resource.ResourceType, String> directoryMap;

  public Directory(Map<String, String> directoryMap) {
    this.directoryMap = directoryMap
      .entrySet()
      .stream()
      .collect(
        Collectors.toMap(
          (e) -> Resource.ResourceType.findByType(e.getKey()),
          (e) -> e.getValue()
        )
      );
  }

  public String get(Resource.ResourceType type) {
    return directoryMap.get(type);
  }

  public String newReg() {
    return directoryMap.get(Resource.ResourceType.NEW_REGISTRATION);
  }

  public String recoverReg() {
    return directoryMap.get(Resource.ResourceType.RECOVER_REGISTRATION);
  }

  public String newAuthz() {
    return directoryMap.get(Resource.ResourceType.NEW_AUTHORIZATION);
  }

  public String newCert() {
    return directoryMap.get(Resource.ResourceType.NEW_CERTIFICATE);
  }

  public String revokeCert() {
    return directoryMap.get(Resource.ResourceType.REVOKE_CERTIFICATE);
  }
}
