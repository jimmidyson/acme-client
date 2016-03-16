package io.fabric8.acme.client.model;

public enum Status {
  UNKNOWN("unknown"),
  PENDING("pending"),
  PROCESSING("processing"),
  VALID("valid"),
  INVALID("invalid"),
  REVOKED("revoked");

  private String status;

  Status(String status) {
    this.status = status;
  }

  public String status() {
    return status;
  }

  static Status findByStatus(String status){
    for(Status v : values()){
      if( v.status.equals(status)){
        return v;
      }
    }
    return null;
  }
}
