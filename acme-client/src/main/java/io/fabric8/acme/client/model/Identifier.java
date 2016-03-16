package io.fabric8.acme.client.model;

import io.sundr.builder.annotations.Buildable;
import net.minidev.json.JSONObject;

@Buildable(
  generateBuilderPackage = true,
  builderPackage = "io.fabric8.acme.client.builder",
  editableEnabled = false
)
public class Identifier {

  private String type;

  private String value;

  public Identifier(String type, String value) {
    this.type = type;
    this.value = value;
  }

  public String getType() {
    return type;
  }

  public String getValue() {
    return value;
  }

  public JSONObject toJSONObject() {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("type", type);
    jsonObject.put("value", value);
    return jsonObject;
  }

  public static Identifier fromJSONObject(JSONObject jsonObject) {
    if (jsonObject == null) {
      return null;
    }

    return new Identifier((String) jsonObject.get("type"), (String) jsonObject.get("value"));
  }
}
