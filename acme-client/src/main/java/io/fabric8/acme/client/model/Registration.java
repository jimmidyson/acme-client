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
package io.fabric8.acme.client.model;

import com.nimbusds.jose.jwk.JWK;
import io.fabric8.acme.client.ACMEClientException;
import io.fabric8.acme.client.BaseResource;
import io.fabric8.acme.client.dsl.Sendable;
import io.sundr.builder.annotations.Buildable;
import io.sundr.builder.annotations.Inline;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.Map;

// See https://ietf-wg-acme.github.io/acme/#rfc.section.5.2 for details

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  inline = @Inline(
    type = Sendable.class,
    prefix = "Sendable",
    value = "send"
  )
)
public class Registration extends BaseResource {

  private JWK jwk;

  private String location;

  private String agreementLocation;

  private String authorizationsLocation;

  private String certificatesLocation;

  private Map<String, String> contact;

  public Registration(JWK jwk, Map<String, String> contact, String location, String agreementLocation, String authorizationsLocation, String certificatesLocation) {
    super(ResourceType.REGISTRATION);
    this.jwk = jwk;
    this.location = location;
    this.agreementLocation = agreementLocation;
    this.authorizationsLocation = authorizationsLocation;
    this.certificatesLocation = certificatesLocation;
    this.contact = contact;
  }

  public JWK getJwk() {
    return jwk;
  }

  public Map<String, String> getContact() {
    return contact;
  }

  public String getLocation() {
    return location;
  }

  public String getAgreementLocation() {
    return agreementLocation;
  }

  public String getAuthorizationsLocation() {
    return authorizationsLocation;
  }

  public String getCertificatesLocation() {
    return certificatesLocation;
  }

  @Override
  public JSONObject toJSONObject() {
    JSONObject json = new JSONObject();
    json.put("resource", getType().type());
    if (contact != null && !contact.isEmpty()) {
      JSONArray contacts = new JSONArray();
      for (Map.Entry<String, String> contact : getContact().entrySet()) {
        contacts.add(contact.getKey() + ":" + contact.getValue());
      }
      json.put("contact", contacts);
    }
    return json;
  }

  public static Registration fromJSONObject(JSONObject jsonObject) {
    RegistrationBuilder builder = new RegistrationBuilder();

    JSONObject jwkObject = (JSONObject) jsonObject.get("key");
    if (jwkObject == null) {
      throw new ACMEClientException("badObject", "Registration JSON is missing required key - see https://ietf-wg-acme.github.io/acme/#rfc.section.5.2");
    }
    try {
      JWK jwk = JWK.parse(jwkObject);
      builder.withJwk(jwk);
    } catch (ParseException e) {
      throw ACMEClientException.launderThrowable(e);
    }

    JSONArray array = (JSONArray) jsonObject.get("contact");
    if (array != null) {
      for (Object obj : array) {
        String c = (String) obj;
        String[] split = c.split(":", 2);
        builder.addToContact(split[0], split[1]);
      }
    }

    String agreementLocation = (String) jsonObject.get("agreement");
    if (agreementLocation != null && !agreementLocation.isEmpty()) {
      builder.withAgreementLocation(agreementLocation);
    }

    String authorizationsLocation = (String) jsonObject.get("authorizations");
    if (authorizationsLocation != null && !authorizationsLocation.isEmpty()) {
      builder.withAuthorizationsLocation(authorizationsLocation);
    }

    String certsLocation = (String) jsonObject.get("certificates");
    if (certsLocation != null && !certsLocation.isEmpty()) {
      builder.withCertificatesLocation(certsLocation);
    }

    return builder.build();
  }
}
