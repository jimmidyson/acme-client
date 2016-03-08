# ACME Java Client

[![Circle CI](https://circleci.com/gh/jimmidyson/acme-client.svg?style=svg)](https://circleci.com/gh/jimmidyson/acme-client) [![codecov.io](https://codecov.io/github/jimmidyson/acme-client/coverage.svg?branch=master)](https://codecov.io/github/jimmidyson/acme-client?branch=master)

This client provides a fluent DSL to interact with [ACME-compliant](https://ietf-wg-acme.github.io/acme/) certificate authorities
to automate the management of certificates.

This client was originally created to integrate with the awesome [Let's Encrypt](https://letsencrypt.org/), the first publicly
available ACME CA but will work with any ACME-compliant CA. If you're looking for a private ACME CA
then you can install your own via the Let's Encrypt OSS project
[Boulder](https://github.com/letsencrypt/boulder).

## Table of Contents
* [Usage](#usage)
  * [Creating a client](#creating-a-client)
  * [Using the DSL](#using-the-dsl)

## Usage

### Creating a client
The easiest way to create a client is:

```java
ACMEClient client = new DefaultACMEClient(server, keyPair);
```

You can also use the `ConfigBuilder` to configure anything in the required config:

```java
Config config = new ConfigBuilder()
                  .withServer(server)
                  .withKeyPair(keyPair)
                  .withJwsAlgorithm(JWSAlgorithm.RS256)
                  .build();
ACMEClient client = new DefaultACMEClient(config);
```

If you're trying to use Let's Encrypt then you can pass in a pre-built config, which includes
certificate pinning:

```java
ACMEClient client = new DefaultACMEClient(new LetsEncryptConfig());
```

And if you're still getting your feet wet with ACME CAs, you can use the Let's Encrypt staging CA
that they kindly provide:

```java
ACMEClient client = new DefaultACMEClient(new LetsEncryptStagingConfig());
```

### Using the DSL
Each part of the DSL allows either the passing in of created objects (which could themselves have
been created via the builder DSLs) to terminal methods, e.g.:

```java
Registration reg = client.registration().create(
        new NewRegistrationBuilder().addToContact("mailto", "noone@nowhere.com").build()
      );
```

Or via inline builder DSLs, e.g.:

```java
Registration reg = client.registration()
        .createNew().addToContact("mailto", "noone@nowhere.com")
        .send();
```
