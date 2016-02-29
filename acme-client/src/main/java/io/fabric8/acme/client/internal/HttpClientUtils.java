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

import io.fabric8.acme.client.Config;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClientUtils {

  private HttpClientUtils() {
  }

  public static OkHttpClient newClient(Config config) {
    OkHttpClient.Builder builder = new OkHttpClient.Builder();

    // Disable redirects.
    builder.followRedirects(false).followSslRedirects(false);

    // Set up request logging.
    Logger reqLogger = LoggerFactory.getLogger(HttpLoggingInterceptor.class);
    if (reqLogger.isTraceEnabled()) {
      HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor();
      loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
      builder.addNetworkInterceptor(loggingInterceptor);
    }

    // Certificate pinning for communicating with the ACME server.
    if (config.getPins() != null && 0 < config.getPins().length) {
      CertificatePinner certificatePinner = new CertificatePinner.Builder()
        .add(config.getServer().getHost(), config.getPins())
        .build();

      builder.certificatePinner(certificatePinner);
    }

    return builder.build();
  }

}
