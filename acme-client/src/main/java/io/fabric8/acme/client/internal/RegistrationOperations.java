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
import io.fabric8.acme.client.dsl.GetCreateUpdatable;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.InlineNewRegistration;
import io.fabric8.acme.client.model.NewRegistration;
import io.fabric8.acme.client.model.Registration;
import io.fabric8.acme.client.model.RegistrationBuilder;
import io.fabric8.acme.client.model.Resource;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.net.HttpURLConnection;

public class RegistrationOperations extends BaseOperations<Registration> implements GetCreateUpdatable<Registration, NewRegistration, InlineNewRegistration> {

  public RegistrationOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer, jwk);
  }

  @Override
  public InlineNewRegistration createNew() {
    return new InlineNewRegistration(this::create);
  }

  @Override
  public Registration create(NewRegistration item) {
    JWSHeader jwsHeader = jwsHeader().build();

    return sendRequest(
      Resource.ResourceType.NEW_REGISTRATION,
      item,
      jwsHeader,
      ((response) -> handleRegistrationResponse(response, item.isAgreeToTerms(), null)),
      HttpURLConnection.HTTP_CREATED
    );
  }

  @Override
  public Registration update(Registration item) {
    JWSHeader jwsHeader = jwsHeader().build();

    return sendRequest(
      item.getLocation(),
      item,
      jwsHeader,
      ((response) -> handleRegistrationResponse(response, item.isAgreeToTerms(), item.getCertificatesLocation())),
      HttpURLConnection.HTTP_ACCEPTED
    );
  }

  private Registration handleRegistrationResponse(Response response, boolean agreeToTerms, String certificatesLocation) {
    try {
      JSONObject jsonObject = JSONParserUtils.parse(response.body().byteStream());
      RegistrationBuilder builder = new RegistrationBuilder(Registration.fromJSONObject(jsonObject));

      if (builder.getCertificatesLocation() == null || builder.getCertificatesLocation().isEmpty()) {
        builder.withCertificatesLocation(certificatesLocation);
      }

      String location = response.header("Location");
      if (location == null || location.isEmpty()) {
        location = response.request().url().toString();
      }
      builder.withLocation(location);

      LinkHeaderFieldParser linkParser = new LinkHeaderFieldParser(response.headers("Link"));

      String oldAgreementLocation = builder.getAgreementLocation();
      String newAgreementLocation = linkParser.getFirstTargetForRelation("terms-of-service");
      builder.withAgreementLocation(newAgreementLocation);
      builder.withAuthorizationsLocation(linkParser.getFirstTargetForRelation("next"));
      builder.withRecoverLocation(linkParser.getFirstTargetForRelation("recover"));

      if (agreeToTerms) {
        if (newAgreementLocation != null && !newAgreementLocation.isEmpty() && !newAgreementLocation.equals(oldAgreementLocation)) {
          return update(builder.build());
        }
      }

      return builder.build();
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  @Override
  public Registration get() {
    JWSHeader jwsHeader = jwsHeader().build();

    return sendRequest(
      Resource.ResourceType.NEW_REGISTRATION,
      new NewRegistration(null, false),
      jwsHeader,
      ((response) -> handleRegistrationResponse(response, false, null)),
      HttpURLConnection.HTTP_CONFLICT
    );
  }
}
