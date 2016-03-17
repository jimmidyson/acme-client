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
import io.fabric8.acme.client.model.Resource;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.ParseException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.concurrent.TimeUnit;

public abstract class BaseOperations<T> {

  protected final Logger logger = LoggerFactory.getLogger(getClass());

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
    return sendRequest(url, item.toJSONObject(), jwsHeader, responseHandler, successCodes);
  }

  protected T sendRequest(String url, JSONObject jsonObject, JWSHeader jwsHeader, ResponseHandler<T> responseHandler, int... successCodes) {
    // Construct the JWS to send on.
    JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(jsonObject));

    signer.sign(jwsObject);

    String compact = jwsObject.serialize();
    RequestBody body = RequestBody.create(REQUEST_MEDIA_TYPE, compact);

    Request request = new Request.Builder()
      .url(url)
      .post(body)
      .build();
    return sendRequest(request, responseHandler, successCodes);
  }

  protected T sendRequest(String url, ResponseHandler<T> responseHandler, int... successCodes) {
    Request request = new Request.Builder()
      .url(url)
      .get()
      .build();
    return sendRequest(request, responseHandler, successCodes);
  }

  protected T sendRequest(Request request, ResponseHandler<T> responseHandler, int... successCodes) {
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

  protected T requestWithRetryAfter(String url, Resource item, JWSHeader jwsHeader, ResponseHandler<T> responseHandler, int successCode, int... retryCodes) {
    try {
      T obj = null;
      int[] allCodes = new int[retryCodes.length + 1];
      System.arraycopy(retryCodes, 0, allCodes, 0, retryCodes.length);
      allCodes[retryCodes.length] = successCode;
      while (obj == null) {
        try {
          obj = sendRequest(
            url,
            item,
            jwsHeader,
            (response) -> {
              String retryAfterHeader = response.header("Retry-After");
              for (int retryCode : retryCodes) {
                if (retryCode == response.code()) {
                  throw new RetryAfterException(retryAfterHeader);
                }
              }
              return responseHandler.handle(response);
            },
            allCodes
          );
        } catch (RetryAfterException e) {
          try {
            TimeUnit.SECONDS.sleep(e.retryAfter);
          } catch (InterruptedException einter) {
            logger.warn("Interrupted sleep during retry", einter);
          }
        }
      }
      return obj;
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

  protected JWK getJwk() {
    return jwk;
  }

  protected JWSAlgorithm getJwsAlgorithm() {
    return jwsAlgorithm;
  }

  private static class RetryAfterException extends RuntimeException {

    private final long retryAfter;

    private RetryAfterException(String retryAfterDate) {
      // Retry-After  = "Retry-After" ":" ( HTTP-date | delta-seconds )
      long retryAfterTemp = 0;
      try {
        TemporalAccessor temp = DateTimeFormatter.RFC_1123_DATE_TIME.parse(retryAfterDate);
        Instant retryAfterInstant = Instant.from(temp);
        retryAfterTemp = Instant.now().until(retryAfterInstant, ChronoUnit.SECONDS);
      } catch (DateTimeParseException e) {
        retryAfterTemp = Long.parseLong(retryAfterDate);
      }
      if (retryAfterTemp < 0) {
        retryAfterTemp = 0;
      }
      retryAfter = retryAfterTemp;
    }
  }
}
