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
package io.fabric8.acme.client;

import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ACMEClientException extends RuntimeException {

  private static final String URN_ACME_ERROR_PREFIX = "urn:acme:error:";
  private static final Map<String, String> ERROR_CODE_MAP = errorCodeMap();
  private int code;
  private String status;
  private String type;
  private String title;
  private String instance;

  public ACMEClientException(String message, Throwable t) {
    super(message, t);
  }

  public ACMEClientException(String type) {
    this(type, ERROR_CODE_MAP.get(type));
  }

  public ACMEClientException(String type, String detail) {
    this(0, null, type, null, detail, null);
  }

  public ACMEClientException(int code, String status, String type, String title, String detail, String instance) {
    super(detail);
    this.code = code;
    this.status = status;
    this.type = type;
    this.title = title;
    this.instance = instance;
  }

  public ACMEClientException(int code, String status, JSONObject jsonObject) {
    this(
      code,
      status,
      (String) jsonObject.get("type"),
      (String) jsonObject.get("title"),
      (String) jsonObject.get("detail"),
      (String) jsonObject.get("instance")
    );
  }

  public ACMEClientException(int code, String status, String err) {
    this(
      code,
      status,
      null,
      null,
      err,
      null
    );
  }

  private static Map<String, String> errorCodeMap() {
    Map<String, String> result = new HashMap<>();
    result.put(URN_ACME_ERROR_PREFIX + "badCSR", "The CSR is unacceptable (e.g., due to a short key)");
    result.put(URN_ACME_ERROR_PREFIX + "badNonce", "The client sent an unacceptable anti-replay nonce");
    result.put(URN_ACME_ERROR_PREFIX + "connection", "The server could not connect to the client for DV");
    result.put(URN_ACME_ERROR_PREFIX + "dnssec", "The server could not validate a DNSSEC signed domain");
    result.put(URN_ACME_ERROR_PREFIX + "malformed", "The request message was malformed");
    result.put(URN_ACME_ERROR_PREFIX + "serverInternal", "The server experienced an internal error");
    result.put(URN_ACME_ERROR_PREFIX + "tls", "The server experienced a TLS error during DV");
    result.put(URN_ACME_ERROR_PREFIX + "unauthorized", "The client lacks sufficient authorization");
    result.put(URN_ACME_ERROR_PREFIX + "unknownHost", "The server could not resolve a domain name");
    result.put(URN_ACME_ERROR_PREFIX + "rateLimited", "The request exceeds a rate limit");
    return Collections.unmodifiableMap(result);
  }

  public static RuntimeException launderThrowable(Throwable cause) {
    if (cause instanceof RuntimeException) {
      return ((RuntimeException) cause);
    } else if (cause instanceof Error) {
      throw ((Error) cause);
    } else {
      throw new ACMEClientException("An error has occurred.", cause);
    }
  }

  public String getStatus() {
    return status;
  }

  public String getType() {
    return type;
  }

  public String getTitle() {
    return title;
  }

  public String getDetail() {
    return getMessage();
  }

  public String getInstance() {
    return instance;
  }

  public int getCode() {
    return code;
  }
}
