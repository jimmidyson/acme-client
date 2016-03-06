package io.fabric8.acme.client.dsl;

public interface GetCreateUpdatable<T, U, V> extends Gettable<T>, Creatable<T, U, V>, Updateable<T> {
}
