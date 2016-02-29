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

import io.fabric8.acme.client.ACMEClientException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.net.URL;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

public class Nonce {

  private OkHttpClient okHttpClient;

  private URL directoryUrl;

  private AtomicReference<String> nonce = new AtomicReference<>();

  public Nonce(OkHttpClient okHttpClient, URL directoryUrl) {
    this.okHttpClient = okHttpClient;
    this.directoryUrl = directoryUrl;
  }

  public String get() {
    String nonce = this.nonce.getAndSet(null);
    if (nonce == null) {
      Request req = new Request.Builder().head().url(directoryUrl).build();
      Response response = null;
      try {
        response = okHttpClient.newCall(req).execute();
      } catch (IOException e) {
        throw ACMEClientException.launderThrowable(e);
      } finally {
        response.body().close();
      }
      String replayNonce = response.header("Replay-Nonce");
      if (replayNonce == null || replayNonce.isEmpty()) {
        throw new ACMEClientException("Response doesn't contain a valid nonce - misconfigured server?");
      }
      return replayNonce;
    }
    return null;
  }

  public void extractNonce(Response response) {
    // Details in https://ietf-wg-acme.github.io/acme/#rfc.section.5.5.1
    String replayNonce = response.header("Replay-Nonce");
    if (replayNonce == null || replayNonce.isEmpty()) {
      throw new ACMEClientException("Response doesn't contain a valid nonce - misconfigured server?");
    }

    // We MUST ignore invalid nonce headers but we need to report this to the
    // caller.
    try {
      // Check the nonce header is properly encoded as a base64url.
      Base64.getUrlDecoder().decode(replayNonce);

      // And store the already encoded nonce.
      this.nonce.set(replayNonce);
    } catch (Exception e) {
      throw ACMEClientException.launderThrowable(e);
    }
  }

}
