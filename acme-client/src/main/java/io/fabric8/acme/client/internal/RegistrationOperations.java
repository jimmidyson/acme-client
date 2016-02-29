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
import io.fabric8.acme.client.dsl.Creatable;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.InlineNewRegistration;
import io.fabric8.acme.client.model.NewRegistration;
import io.fabric8.acme.client.model.Registration;
import io.fabric8.acme.client.model.RegistrationBuilder;
import io.fabric8.acme.client.model.Resource;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;

public class RegistrationOperations extends BaseOperations<Registration> implements Creatable<Registration, NewRegistration, InlineNewRegistration> {

  private JWK jwk;

  public RegistrationOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer);
    this.jwk = jwk;
  }

  @Override
  public Registration create(NewRegistration item) {
    JWSHeader jwsHeader = noncedJwsHeader()
      .jwk(jwk.toPublicJWK())
      .build();

    return sendRequest(
      Resource.ResourceType.NEW_REGISTRATION,
      item,
      jwsHeader,
      (response) -> {
        try {
          JSONObject jsonObject = JSONParserUtils.parse(response.body().byteStream());
          RegistrationBuilder builder = new RegistrationBuilder(Registration.fromJSONObject(jsonObject));

          LinkHeaderFieldParser linkParser = new LinkHeaderFieldParser(response.headers("Link"));

          // Check if locations are in the response headers instead
          if (builder.getAgreementLocation() == null || builder.getAgreementLocation().isEmpty()) {
            builder.withAgreementLocation(linkParser.getFirstTargetForRelation("terms-of-service"));
          }
          if (builder.getAuthorizationsLocation() == null || builder.getAuthorizationsLocation().isEmpty()) {
            builder.withAuthorizationsLocation(linkParser.getFirstTargetForRelation("next"));
          }

          return builder.build();
        } catch (Exception e) {
          throw ACMEClientException.launderThrowable(e);
        }
      }
    );
  }

  @Override
  public InlineNewRegistration createNew() {
    return new InlineNewRegistration(this::create);
  }

}
