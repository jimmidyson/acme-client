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
import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.ACMEClientException;
import io.fabric8.acme.client.dsl.Readyable;
import io.fabric8.acme.client.dsl.UseLocatable;
import io.fabric8.acme.client.model.Challenge;
import io.fabric8.acme.client.model.ChallengeWithToken;
import io.fabric8.acme.client.model.Directory;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.net.HttpURLConnection;

public class ChallengeOperations extends BaseOperations<Challenge>
  implements UseLocatable<Challenge, Readyable<Challenge>> {

  public ChallengeOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer, jwk);
  }

  @Override
  public Readyable<Challenge> at(String location) {
    return use(sendRequest(location, this::handleChallengeResponse, HttpURLConnection.HTTP_OK));
  }

  @Override
  public Readyable<Challenge> use(Challenge obj) {
    return () -> {
      try {
        return sendRequest(
          obj.getUri(),
          readyChallenge(obj),
          jwsHeader().build(),
          this::handleChallengeResponse,
          HttpURLConnection.HTTP_ACCEPTED
        );
      } catch (Exception e) {
        throw ACMEClientException.launderThrowable(e);
      }
    };
  }

  private Challenge handleChallengeResponse(Response response) {
    try {
      JSONObject jsonObject = JSONParserUtils.parse(response.body().byteStream());
      return Challenge.fromJSONObject(jsonObject);
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  private JSONObject readyChallenge(Challenge challenge) throws JOSEException {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("resource", "challenge");

    if (challenge instanceof ChallengeWithToken) {
      jsonObject.put("keyAuthorization", ((ChallengeWithToken) challenge).getToken() + "." + getJwk().computeThumbprint().toString());
    }

    return jsonObject;
  }
}
