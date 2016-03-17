package io.fabric8.acme.client.dsl;

public interface Locatable<T> {

  T at(String location);

}
