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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * Borrowed from https://svn.apache.org/repos/asf/jackrabbit/trunk/jackrabbit-webdav/src/main/java/org/apache/jackrabbit/webdav/util/LinkHeaderFieldParser.java - thanks!
 */

/**
 * Simple parser for HTTP Link header fields, as defined in RFC 5988.
 */
public class LinkHeaderFieldParser {

  /**
   * the default logger
   */
  private static Logger log = LoggerFactory.getLogger(LinkHeaderFieldParser.class);

  private final List<LinkRelation> relations;

  public LinkHeaderFieldParser(List<String> fieldValues) {
    List<LinkRelation> tmp = new ArrayList<LinkRelation>();
    if (fieldValues != null) {
      for (String value : fieldValues) {
        addFields(tmp, value);
      }
    }
    relations = Collections.unmodifiableList(tmp);
  }

  public LinkHeaderFieldParser(Enumeration<?> en) {
    if (en != null && en.hasMoreElements()) {
      List<LinkRelation> tmp = new ArrayList<LinkRelation>();

      while (en.hasMoreElements()) {
        addFields(tmp, en.nextElement().toString());
      }
      relations = Collections.unmodifiableList(tmp);
    } else {
      // optimize case of no Link headers
      relations = Collections.emptyList();
    }
  }

  public String getFirstTargetForRelation(String relationType) {

    for (LinkRelation lr : relations) {

      String relationNames = lr.getParameters().get("rel");
      if (relationNames != null) {

        // split rel value on whitespace
        for (String rn : relationNames.toLowerCase(Locale.ENGLISH)
          .split("\\s")) {
          if (relationType.equals(rn)) {
            return lr.getTarget();
          }
        }
      }
    }

    return null;
  }

  // A single header field instance can contain multiple, comma-separated
  // fields.
  private void addFields(List<LinkRelation> l, String fieldValue) {

    boolean insideAngleBrackets = false;
    boolean insideDoubleQuotes = false;

    for (int i = 0; i < fieldValue.length(); i++) {

      char c = fieldValue.charAt(i);

      if (insideAngleBrackets) {
        insideAngleBrackets = c != '>';
      } else if (insideDoubleQuotes) {
        insideDoubleQuotes = c != '"';
        if (c == '\\' && i < fieldValue.length() - 1) {
          // skip over next character
          c = fieldValue.charAt(++i);
        }
      } else {
        insideAngleBrackets = c == '<';
        insideDoubleQuotes = c == '"';

        if (c == ',') {
          String v = fieldValue.substring(0, i);
          if (v.length() > 0) {
            try {
              l.add(new LinkRelation(v));
            } catch (Exception ex) {
              log.warn("parse error in Link Header field value",
                ex);
            }
          }
          addFields(l, fieldValue.substring(i + 1));
          return;
        }
      }
    }

    if (fieldValue.length() > 0) {
      try {
        l.add(new LinkRelation(fieldValue));
      } catch (Exception ex) {
        log.warn("parse error in Link Header field value", ex);
      }
    }
  }

  private static class LinkRelation {

    private static Pattern P = Pattern.compile("\\s*<(.*)>\\s*(.*)");

    private String target;
    private Map<String, String> parameters;

    /**
     * Parses a single link relation, consisting of <URI> and optional
     * parameters.
     *
     * @param field
     *            field value
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public LinkRelation(String field) throws Exception {

      // find the link target using a regexp
      Matcher m = P.matcher(field);
      if (!m.matches()) {
        throw new Exception("illegal Link header field value:" + field);
      }

      target = m.group(1);

      // pass the remainder to the generic parameter parser
      List<NameValuePair> params = (List<NameValuePair>) new ParameterParser()
        .parse(m.group(2), ';');

      if (params.size() == 0) {
        parameters = Collections.emptyMap();
      } else if (params.size() == 1) {
        NameValuePair nvp = params.get(0);
        parameters = Collections.singletonMap(nvp.getName()
          .toLowerCase(Locale.ENGLISH), nvp.getValue());
      } else {
        parameters = new HashMap<String, String>();
        for (NameValuePair p : params) {
          if (null != parameters.put(
            p.getName().toLowerCase(Locale.ENGLISH),
            p.getValue())) {
            throw new Exception("duplicate parameter + "
              + p.getName() + " field ignored");
          }
        }
      }
    }

    public String getTarget() {
      return target;
    }

    public Map<String, String> getParameters() {
      return parameters;
    }

    public String toString() {
      return target + " " + parameters;
    }
  }

  private static final class NameValuePair {
    private String name;

    private String value;

    public NameValuePair(String name, String value) {
      this.name = name;
      this.value = value;
    }

    public String getName() {
      return name;
    }

    public String getValue() {
      return value;
    }
  }

  /**
   * A simple parser intended to parse sequences of name/value pairs.
   * Parameter values are exptected to be enclosed in quotes if they
   * contain unsafe characters, such as '=' characters or separators.
   * Parameter values are optional and can be omitted.
   *
   * <p>
   *  <code>param1 = value; param2 = "anything goes; really"; param3</code>
   * </p>
   *
   * @author <a href="mailto:oleg@ural.ru">Oleg Kalnichevski</a>
   *
   * @since 3.0
   */
  private static final class ParameterParser {

    /** String to be parsed */
    private char[] chars = null;

    /** Current position in the string */
    private int pos = 0;

    /** Maximum position in the string */
    private int len = 0;

    /** Start of a token */
    private int i1 = 0;

    /** End of a token */
    private int i2 = 0;

    /** Default ParameterParser constructor */
    public ParameterParser() {
      super();
    }


    /** Are there any characters left to parse? */
    private boolean hasChar() {
      return this.pos < this.len;
    }


    /** A helper method to process the parsed token. */
    private String getToken(boolean quoted) {
      // Trim leading white spaces
      while ((i1 < i2) && (Character.isWhitespace(chars[i1]))) {
        i1++;
      }
      // Trim trailing white spaces
      while ((i2 > i1) && (Character.isWhitespace(chars[i2 - 1]))) {
        i2--;
      }
      // Strip away quotes if necessary
      if (quoted) {
        if (((i2 - i1) >= 2)
          && (chars[i1] == '"')
          && (chars[i2 - 1] == '"')) {
          i1++;
          i2--;
        }
      }
      String result = null;
      if (i2 >= i1) {
        result = new String(chars, i1, i2 - i1);
      }
      return result;
    }


    /** Is given character present in the array of characters? */
    private boolean isOneOf(char ch, char[] charray) {
      boolean result = false;
      for (int i = 0; i < charray.length; i++) {
        if (ch == charray[i]) {
          result = true;
          break;
        }
      }
      return result;
    }


    /** Parse out a token until any of the given terminators
     * is encountered. */
    private String parseToken(final char[] terminators) {
      char ch;
      i1 = pos;
      i2 = pos;
      while (hasChar()) {
        ch = chars[pos];
        if (isOneOf(ch, terminators)) {
          break;
        }
        i2++;
        pos++;
      }
      return getToken(false);
    }


    /** Parse out a token until any of the given terminators
     * is encountered. Special characters in quoted tokens
     * are escaped. */
    private String parseQuotedToken(final char[] terminators) {
      char ch;
      i1 = pos;
      i2 = pos;
      boolean quoted = false;
      boolean charEscaped = false;
      while (hasChar()) {
        ch = chars[pos];
        if (!quoted && isOneOf(ch, terminators)) {
          break;
        }
        if (!charEscaped && ch == '"') {
          quoted = !quoted;
        }
        charEscaped = (!charEscaped && ch == '\\');
        i2++;
        pos++;

      }
      return getToken(true);
    }

    /**
     * Extracts a list of {@link NameValuePair}s from the given string.
     *
     * @param str the string that contains a sequence of name/value pairs
     * @return a list of {@link NameValuePair}s
     *
     */
    public List parse(final String str, char separator) {

      if (str == null) {
        return new ArrayList();
      }
      return parse(str.toCharArray(), separator);
    }

    /**
     * Extracts a list of {@link NameValuePair}s from the given array of
     * characters.
     *
     * @param chars the array of characters that contains a sequence of
     * name/value pairs
     *
     * @return a list of {@link NameValuePair}s
     */
    public List parse(final char[] chars, char separator) {

      if (chars == null) {
        return new ArrayList();
      }
      return parse(chars, 0, chars.length, separator);
    }


    /**
     * Extracts a list of {@link NameValuePair}s from the given array of
     * characters.
     *
     * @param chars the array of characters that contains a sequence of
     * name/value pairs
     * @param offset - the initial offset.
     * @param length - the length.
     *
     * @return a list of {@link NameValuePair}s
     */
    public List parse(final char[] chars, int offset, int length, char separator) {

      if (chars == null) {
        return new ArrayList();
      }
      List params = new ArrayList();
      this.chars = chars;
      this.pos = offset;
      this.len = length;

      String paramName = null;
      String paramValue = null;
      while (hasChar()) {
        paramName = parseToken(new char[] {'=', separator});
        paramValue = null;
        if (hasChar() && (chars[pos] == '=')) {
          pos++; // skip '='
          paramValue = parseQuotedToken(new char[] {separator});
        }
        if (hasChar() && (chars[pos] == separator)) {
          pos++; // skip separator
        }
        if (paramName != null && !(paramName.equals("") && paramValue == null)) {
          params.add(new NameValuePair(paramName, paramValue));
        }
      }
      return params;
    }
  }
}
