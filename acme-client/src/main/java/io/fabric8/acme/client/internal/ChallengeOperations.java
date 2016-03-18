/**
 * Copyright (C) 2016 Red Hat, Inc.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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
import io.fabric8.acme.client.dsl.PrepareReadyable;
import io.fabric8.acme.client.dsl.UseLocatable;
import io.fabric8.acme.client.model.Challenge;
import io.fabric8.acme.client.model.ChallengeWithToken;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.Dns01Challenge;
import io.fabric8.acme.client.model.Http01Challenge;
import io.fabric8.acme.client.model.TlsSni01Challenge;
import net.minidev.json.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.net.HttpURLConnection;

public class ChallengeOperations extends BaseOperations<Challenge>
  implements UseLocatable<Challenge, PrepareReadyable<Challenge>>, PrepareReadyable<Challenge> {

  private Challenge challenge;

  public ChallengeOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    super(directory, okHttpClient, nonce, jwsAlgorithm, signer, jwk);
  }

  private ChallengeOperations(Challenge challenge, ChallengeOperations orig) {
    super(orig);
    this.challenge = challenge;
  }

  @Override
  public PrepareReadyable<Challenge> at(String location) {
    return use(sendRequest(location, this::handleChallengeResponse, HttpURLConnection.HTTP_OK));
  }

  @Override
  public PrepareReadyable<Challenge> use(Challenge obj) {
    return new ChallengeOperations(obj, this);
  }

  public Challenge prepare() {
    try {
      switch (challenge.getType()) {
        case "dns-01":
          Dns01Challenge dns01Challenge = (Dns01Challenge) challenge;
          return new Dns01Challenge(
            dns01Challenge.getToken(),
            dns01Challenge.getStatus(),
            dns01Challenge.getUri(),
            dns01Challenge.getToken() + "." + getJwk().computeThumbprint().toString()
          );
        case "http-01":
          Http01Challenge http01Challenge = (Http01Challenge) challenge;
          return new Http01Challenge(
            http01Challenge.getToken(),
            http01Challenge.getStatus(),
            http01Challenge.getUri(),
            http01Challenge.getToken() + "." + getJwk().computeThumbprint().toString()
          );
        case "tls-sni-01":
          TlsSni01Challenge tlsSni01Challenge = (TlsSni01Challenge) challenge;
          return new Http01Challenge(
            tlsSni01Challenge.getToken(),
            tlsSni01Challenge.getStatus(),
            tlsSni01Challenge.getUri(),
            tlsSni01Challenge.getToken() + "." + getJwk().computeThumbprint().toString()
          );
        default:
          return challenge;
      }
    } catch (JOSEException e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  public Challenge ready() {
    try {
      return sendRequest(
        challenge.getUri(),
        readyChallenge(challenge),
        jwsHeader().build(),
        this::handleChallengeResponse,
        HttpURLConnection.HTTP_ACCEPTED
      );
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
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
      ChallengeWithToken challengeWithToken = (ChallengeWithToken) challenge;
      String keyAuthorization = challengeWithToken.getKeyAuthorization();
      if (keyAuthorization == null || keyAuthorization.isEmpty()) {
        keyAuthorization = challengeWithToken.getToken() + "." + getJwk().computeThumbprint().toString();
      }
      jsonObject.put("keyAuthorization", keyAuthorization);
    }

    return jsonObject;
  }
}
