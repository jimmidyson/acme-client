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
package io.fabric8.acme.client.internal;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.ACMEClientException;
import io.fabric8.acme.client.dsl.CreateLocatable;
import io.fabric8.acme.client.dsl.Gettable;
import io.fabric8.acme.client.model.Authorization;
import io.fabric8.acme.client.model.AuthorizationBuilder;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.NewAuthorization;
import io.fabric8.acme.client.model.Resource;
import io.fabric8.acme.client.model.SendableNewAuthorization;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.net.HttpURLConnection;

public class AuthorizationOperations extends BaseOperations<Authorization>
  implements CreateLocatable<Authorization, NewAuthorization, SendableNewAuthorization, Gettable<Authorization>> {

  public AuthorizationOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer, jwk);
  }

  @Override
  public SendableNewAuthorization createNew() {
    return new SendableNewAuthorization(this::create);
  }

  @Override
  public Authorization create(NewAuthorization item) {
    JWSHeader jwsHeader = jwsHeader().build();

    return sendRequest(
      Resource.ResourceType.NEW_AUTHORIZATION,
      item,
      jwsHeader,
      this::handleAuthorizationResponse,
      HttpURLConnection.HTTP_CREATED
    );
  }

  private Authorization handleAuthorizationResponse(Response response) {
    try {
      JSONObject jsonObject = JSONParserUtils.parse(response.body().byteStream());
      AuthorizationBuilder builder = new AuthorizationBuilder(Authorization.fromJSONObject(jsonObject));
      String location = response.header("Location");
      if (location == null || location.isEmpty()) {
        location = response.request().url().toString();
      }
      builder.withLocation(location);
      return builder.build();
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  @Override
  public Gettable<Authorization> at(String location) {
    return () -> sendRequest(location, this::handleAuthorizationResponse, HttpURLConnection.HTTP_OK);
  }
}
