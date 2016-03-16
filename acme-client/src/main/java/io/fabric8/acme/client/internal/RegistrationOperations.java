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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.ACMEClientException;
import io.fabric8.acme.client.dsl.GetCreateUpdateEditKeyUpdateRecoverable;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.NewRegistration;
import io.fabric8.acme.client.model.RecoveryRegistration;
import io.fabric8.acme.client.model.Registration;
import io.fabric8.acme.client.model.RegistrationBuilder;
import io.fabric8.acme.client.model.Resource;
import io.fabric8.acme.client.model.SendableNewRegistration;
import io.fabric8.acme.client.model.SendableRecoveryRegistration;
import io.fabric8.acme.client.model.SendableRegistration;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.net.HttpURLConnection;
import java.security.KeyPair;

public class RegistrationOperations extends BaseOperations<Registration> implements GetCreateUpdateEditKeyUpdateRecoverable<Registration, NewRegistration, SendableNewRegistration, SendableRegistration, SendableRecoveryRegistration> {

  public RegistrationOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer, jwk);
  }

  @Override
  public SendableNewRegistration createNew() {
    return new SendableNewRegistration(this::create);
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
      String location = response.header("Location");
      if (location == null || location.isEmpty()) {
        location = response.request().url().toString();
      }

      JSONObject jsonObject = JSONParserUtils.parse(response.body().byteStream());
      RegistrationBuilder builder = new RegistrationBuilder(Registration.fromJSONObject(jsonObject));

      if (builder.getCertificatesLocation() == null || builder.getCertificatesLocation().isEmpty()) {
        builder.withCertificatesLocation(certificatesLocation);
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
      this::handleGetRegistrationResponse,
      HttpURLConnection.HTTP_CONFLICT, HttpURLConnection.HTTP_CREATED
    );
  }

  private Registration handleGetRegistrationResponse(Response response) {
    if (response.code() == HttpURLConnection.HTTP_CONFLICT) {
      String location = response.header("Location");
      if (location != null && !location.isEmpty()) {
        Registration reg = new RegistrationBuilder().withLocation(location).build();
        return update(reg);
      }
    }
    return handleRegistrationResponse(response, false, null);
  }

  @Override
  public SendableRegistration edit() {
    return new SendableRegistration(get(), this::update);
  }

  // See https://ietf-wg-acme.github.io/acme/#account-key-roll-over
  @Override
  public void updateKey(KeyPair newKeyPair) {
    try {
      JSONObject oldKey = new JSONObject();
      oldKey.put("resource", "reg");
      oldKey.put("oldKey", getJwk().computeThumbprint());

      JWK newJWK = JWKUtils.jwkFromPublicKey(newKeyPair.getPublic());

      JWSHeader oldKeyHeader = new JWSHeader.Builder(getJwsAlgorithm()).jwk(newJWK).build();
      JWSObject oldJwsObject = new JWSObject(oldKeyHeader, new Payload(oldKey));

      new Signer(newKeyPair.getPrivate()).sign(oldJwsObject);

      JSONObject newKey = new JSONObject();
      newKey.put("resource", "reg");
      newKey.put("newKey", oldJwsObject.serialize());

      sendRequest(get().getLocation(), newKey, jwsHeader().build(), (response) -> null, HttpURLConnection.HTTP_ACCEPTED);
    } catch (JOSEException e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  @Override
  public SendableRecoveryRegistration recovery() {
    return new SendableRecoveryRegistration(this::recover);
  }

  private Registration recover(RecoveryRegistration recoveryRegistration) {
    Registration stubRegistration = sendRequest(
      Resource.ResourceType.RECOVER_REGISTRATION,
      recoveryRegistration,
      jwsHeader().build(),
      (response) -> handleRegistrationResponse(response, false, null),
      HttpURLConnection.HTTP_CREATED
    );

    Registration emptyReg = new RegistrationBuilder().build();

    return requestWithRetryAfter(
      stubRegistration.getLocation(),
      emptyReg,
      jwsHeader().build(),
      ((response) -> handleRegistrationResponse(response, false, null)),
      HttpURLConnection.HTTP_OK,
      HttpURLConnection.HTTP_ACCEPTED
    );
  }

}
