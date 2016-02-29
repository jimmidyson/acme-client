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

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

public class JSONParserUtils {

  private static final JSONParser JSON_PARSER = new JSONParser(JSONParser.MODE_JSON_SIMPLE);

  private static final Logger logger = LoggerFactory.getLogger(JSONParserUtils.class);

  private JSONParserUtils() {
  }

  public static JSONObject parse(String json) throws ParseException, IOException {
    return (JSONObject) JSON_PARSER.parse(json);
  }

  public static JSONObject parse(InputStream json) throws ParseException, IOException {
    JSONObject jsonObject = (JSONObject) JSON_PARSER.parse(json);
    try {
      json.close();
    } catch (IOException e) {
      logger.error("Cannot close JSON stream", e);
    }
    return jsonObject;
  }
}
