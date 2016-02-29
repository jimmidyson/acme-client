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

public class InlineNewRegistration extends NewRegistrationFluentImpl<InlineNewRegistration>
  implements Sendable<Registration> {

  private final NewRegistrationBuilder builder;

  private final Callback<NewRegistration, Registration> callback;

  public InlineNewRegistration(Callback<NewRegistration, Registration> callback) {
    this.builder = new NewRegistrationBuilder(this);
    this.callback = callback;
  }

  public InlineNewRegistration(Callback<NewRegistration, Registration> callback, NewRegistrationBuilder builder) {
    this.builder = builder;
    this.callback = callback;
  }

  @Override
  public Registration send() {
    return callback.call(builder.build());
  }

}
