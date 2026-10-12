# Mongo JWT Claims

This is a service to exchange a bearer JWT token for another one with extra claims from a MongoDB query, which are merged into the provided token. The provided tokens are verified with the configured issuers. The issued tokens are signed with a key that is provided in a file. Although this is not a real OIDC IDP, the path `.well-known/openid-configuration` is supported. This allows others to verify its tokens in the standard way.

## Configuration

The format of the configuration file can be anything described in [Rust Config](https://docs.rs/config/latest/config/). The value of the environment variable `CONFIG_FILE` is added as a potential source. The default location is the path `conf/application`, relative to the working directory.

|Entry|Mandatory|Default value|Description|
|---|---|---|---|
|cert-folder|No|None|A folder that should contain the files `tls.crt` and `tls.key`. When it is set, a TLS listener will be created.|
|issuers|Yes|None|The array of issuers from which tokens are accepted.|
|issuers.iss|Yes|None|The URL of the issuer.|
|issuers.aud|No|None|The array of audiences that are accepted. It is highly recommended to set this to avoid privilege elevation issues.|
|key-file|Yes|None|The file that contains the key with which the tokens are signed. It should contain a JSON object with the fields `alg`, `kid` and `pem`. Whenever the file changes, it is reloaded. This allows for key rotation.|
|jwks-file|Yes|None|A JSON file with the JSON Web Key Set. It is served in response to a `GET` request on the path `/jwks`. When the file changes, it is reloaded. It should be consistent with `key-file`.|
|log-level|No|info|The log level as defined in the [log](https://docs.rs/log/latest/log/) crate. If it is not set, the environment variable `RUST_LOG` will be tried.|
|mongo.database|Yes|None|The MongoDB database.|
|mongo.handlers|No|None|The array of handlers for each supported path.|
|mongo.handlers.aggregation|Yes|None|The aggregation pipeline, either as YAML or as a JSON string. Fields in the provided bearer token can be consumed with `${<field>}`. URL parameters on the request can be consumed with `$$<parameter>`.|
|mongo.handlers.collection|Yes|None|The MongoDB collection that is used for the query.|
|mongo.handlers.path|Yes|None|The path that is served by the handler.|
|mongo.uri|Yes|None|The MongoDB connection string.|
|otel|No|None|The OpenTelemetry [configuration](https://docs.rs/otel-config/latest/otel_config/struct.Providers.html#method.form_config).|
|this-issuer|Yes|None|The URL of the issuer. It will be used as the value of the `iss` claim in the generated tokens.|

## Running It

The CLI has only an option to set the port, the default value of which is 8080.

```
> mongo-jwt-claims --port 8888
```

## Docker

Docker images can be found at [https://hub.docker.com/repository/docker/wdonne/mongo-jwt-claims](https://hub.docker.com/repository/docker/wdonne/mongo-jwt-claims).

## Kubernetes

Install the service as follows:

```bash
helm repo add wdonne https://wdonne.github.io/helm
helm repo update
helm install mongo-jwt-claims wdonne/mongo-jwt-claims --namespace mongo-jwt-claims --create-namespace
```