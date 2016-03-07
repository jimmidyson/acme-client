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

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.ACMEClientException;
import io.fabric8.acme.client.model.Directory;
import io.fabric8.acme.client.model.Registration;
import io.fabric8.acme.client.model.Resource;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.ParseException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;

public abstract class BaseOperations<T> {

  private static final MediaType REQUEST_MEDIA_TYPE = MediaType.parse(JOSEObject.MIME_TYPE_COMPACT);

  private Directory directory;

  private OkHttpClient okHttpClient;

  private Nonce nonce;

  private JWSAlgorithm jwsAlgorithm;

  private Signer signer;

  private JWK jwk;

  public BaseOperations(Directory directory, OkHttpClient okHttpClient, Nonce nonce, JWSAlgorithm jwsAlgorithm, Signer signer, JWK jwk) {
    this.directory = directory;
    this.okHttpClient = okHttpClient;
    this.nonce = nonce;
    this.jwsAlgorithm = jwsAlgorithm;
    this.signer = signer;
    this.jwk = jwk;
  }

  protected T sendRequest(Resource.ResourceType resourceType, Resource item, JWSHeader jwsHeader, ResponseHandler<T> responseHandler, int... successCodes) {
    return sendRequest(directory.get(resourceType), item, jwsHeader, responseHandler, successCodes);
  }

  protected T sendRequest(String url, Resource item, JWSHeader jwsHeader, ResponseHandler<T> responseHandler, int... successCodes) {
    // Construct the JWS to send on.
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(item.toJSONObject()));

    signer.sign(jwsObject);

    String compact = jwsObject.serialize();
    RequestBody body = RequestBody.create(REQUEST_MEDIA_TYPE, compact);

    Request request = new Request.Builder()
      .url(url)
      .post(body)
      .build();

    try {
      Response response = okHttpClient.newCall(request).execute();
      try {
        assertSuccessfulResponse(response, successCodes);
        nonce.extractNonce(response);
        return responseHandler.handle(response);
      } finally {
        response.body().close();
      }
    } catch (IOException e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  protected JWSHeader.Builder jwsHeader() {
    return new JWSHeader.Builder(jwsAlgorithm)
      .customParam("nonce", nonce.get())
      .jwk(jwk);
  }

  private void assertSuccessfulResponse(Response response, int... expectedStatusCode) {
    for (int code : expectedStatusCode) {
      if (response.code() == code) {
        return;
      }
    }
    String detail = response.message();
    try {
      detail = response.body().string();
      JSONObject parsedResponse = JSONParserUtils.parse(detail);
      throw new ACMEClientException(response.code(), response.message(), parsedResponse);
    } catch (ParseException | IOException e) {
      throw new ACMEClientException(response.code(), response.message(), detail);
    }
  }

  public abstract Registration update(Registration item);
}
