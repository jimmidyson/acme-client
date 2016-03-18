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
package io.fabric8.acme.client;

import io.fabric8.acme.client.dsl.CreateLocatable;
import io.fabric8.acme.client.dsl.GetCreateUpdateEditKeyUpdateRecoverable;
import io.fabric8.acme.client.dsl.Gettable;
import io.fabric8.acme.client.dsl.PrepareReadyable;
import io.fabric8.acme.client.dsl.UseLocatable;
import io.fabric8.acme.client.model.Authorization;
import io.fabric8.acme.client.model.Challenge;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.NewAuthorization;
import io.fabric8.acme.client.model.NewRegistration;
import io.fabric8.acme.client.model.Registration;
import io.fabric8.acme.client.model.SendableNewAuthorization;
import io.fabric8.acme.client.model.SendableNewRegistration;
import io.fabric8.acme.client.model.SendableRecoveryRegistration;
import io.fabric8.acme.client.model.SendableRegistration;

public interface ACMEClient extends AutoCloseable{

  Directory directory();

  GetCreateUpdateEditKeyUpdateRecoverable<Registration, NewRegistration, SendableNewRegistration, SendableRegistration, SendableRecoveryRegistration> registration();

  CreateLocatable<Authorization, NewAuthorization, SendableNewAuthorization, Gettable<Authorization>> authorization();

  UseLocatable<Challenge, PrepareReadyable<Challenge>> challenges();

  void close();

}
