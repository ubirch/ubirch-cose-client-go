# UBIRCH COSE client (go)

### Interface Description

*see specification: [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)*

The COSE service expects either original data as JSON or CBOR object, or the SHA256 hash of a
[CBOR encoded signature structure](https://tools.ietf.org/html/rfc8152#section-4.4) (`Sig_structure`)
for a [COSE Single Signer Data Object](https://tools.ietf.org/html/rfc8152#section-4.2) (`COSE_Sign1`).

When receiving a JSON data package, the service will encode it
with [Canonical CBOR](https://tools.ietf.org/html/rfc7049#section-3.9) rules.

| Method | Path | Content-Type | Description |
|--------|------|--------------|-------------|
| POST | `/<UUID>/anchor` | `"application/json"` | original data (JSON data package) |
| POST | `/<UUID>/anchor` | `"application/cbor"` | original data (CBOR encoded) |
| POST | `/<UUID>/cbor/hash` | `application/octet-stream` | [SHA256 hash (binary)](#how-to-create-valid-cose-objects-without-sending-original-data-to-the-service) |
| POST | `/<UUID>/cbor/hash` | `text/plain` | [SHA256 hash (base64 string repr.)](#how-to-create-valid-cose-objects-without-sending-original-data-to-the-service) |

To send the **hex** string representation of the hash (instead of base64), the `Content-Transfer-Encoding`-header can be
used.

```json
{"Content-Type": "text/plain", "Content-Transfer-Encoding": "hex"}
```

### Response

The service returns a ECDSA P-256 signed `COSE_Sign1` object.

```fundamental
COSE_Sign1 = [
    protected : serialized_map,  # serialized CBOR encoded protected header map (b'\xA1\x01\x26') => {1: -7} => {"alg": <ES256>}
    unprotected : header_map,    # CBOR encoded unprotected header map \xA1\x04\x50\xA7\xEA\x87\xF4\xCF\xC4\x45\x67\x8B\xD1\x0B\x4C\x15\xEA\xF5\x5E => {4: b'\xA7\xEA\x87\xF4\xCF\xC4\x45\x67\x8B\xD1\x0B\x4C\x15\xEA\xF5\x5E'} => {"kid": <UUID>}
    payload : bstr,              # original data or SHA256 hash (depending on request content)
    signature : bstr             # ECDSA P-256 signature of the SHA256 hash of the CBOR encoded COSE_Sign1 signature structure
]
```

The returned `COSE_Sign1` object contains the request data (original data or SHA256 hash) as payload and the
following [header parameters](https://tools.ietf.org/html/rfc8152#section-3):

| Bucket | Name | Label | Value | Description |
|--------|------|-------|-------|-------------|
| protected header | "alg" | 1 | -7 ([ES256](https://cose-wg.github.io/cose-spec/#rfc.section.8.1)) | Identifier for the cryptographic algorithm used for signing |
| unprotected header | "kid" | 4 |  <SKID, i.e. the first 8 bytes of the sha256 hash of the DER-encoded X.509 certificate of the public key (according to the hcert specification)> | Key identifier |

**Note, that the `COSE_Sign1` object will not be verifiable, if it does not have the original data as payload.**

If only a hash (and not the original data) is sent to the COSE service, the original data must be inserted into the
payload field of the returned `COSE_Sign1` object afterwards, in order to get a valid (verifiable) COSE object.

### How to create valid COSE objects without sending original data to the service

Here are the steps to create a valid `COSE_Sign1` object with the appropriate hash, which needs to be sent to the COSE
service.

*These steps are only necessary when using the `/hash`-endpoint of the COSE service. When sending original data, this is
done internally by the service.*

1. Create a [Sig_structure](https://tools.ietf.org/html/rfc8152#section-4.4) with the following fields.

    ```fundamental
    Sig_structure = [
        context : "Signature1",           # text string identifying the context of the signature
        body_protected : serialized_map,  # the serialized CBOR encoded protected header map of the `COSE_Sign1` object (b'\xA1\x01\x26') => {1: -7} => {"alg": <ES256>}
        external_aad : bstr,              # empty (b'') or protected application attributes
        payload : bstr                    # serialized CBOR encoded original data (b'<payload>')
    ]
    ```

    - context: `"Signature1"`           (identifier for `COSE_Sign1`)
    - body_protected: `b'\xA1\x01\x26'` (identifier for `ECDSA P-256` signing algorithm)
    - external_aad: `b''`               (*optional:*
      [externally supplied data](https://tools.ietf.org/html/rfc8152#section-4.3) -> not part of the COSE object)
    - payload: *here goes the CBOR encoded original data*

2. Create the value *ToBeSigned* by encoding the `Sig_structure` to a byte string, using the CBOR-encoding described
   in [Section 14](https://cose-wg.github.io/cose-spec/#rfc.section.14).

3. Create the SHA256 hash of the CBOR encoded Sig_structure.

4. Send hash to COSE service.

5. CBOR-decode response into `COSE_Sign1` structure with the following fields.

    ```fundamental
    COSE_Sign1 = [
        protected : bstr,
        unprotected : map,
        payload : bstr,
        signature : bstr
    ]
    ```

6. Insert original data into the `payload` field of the array.

**Pseudo-Code:**

```fundamental
Sig_structure       = ['Signature1', b'\xA1\x01\x26', b'', b'payload bytes']
ToBeSigned          = CBOR_encode(Sig_structure)
SHA256              = SHA256_hash(ToBeSigned)
COSE_Sign1_bytes    = send_to_COSE_service(SHA256)
COSE_Sign1          = CBOR_decode(COSE_Sign1_bytes)
COSE_Sign1->payload = b'payload bytes'
```

### TCP Address

When running the client locally, the default base address is:

`http://localhost:8080`

or, if TLS is enabled:

`https://localhost:8080`

> See [how to set a different TCP address/port for the client](#set-tcp-address).

### CURL Request Examples:

- original data (JSON):
  ```console
  curl localhost:8080/ba70ad8b-a564-4e58-9a3b-224ac0f0153f/cbor \
    -H "X-Auth-Token: IM+NW4iz3YtTBZyHnW+RtnArBXEK7eKy0do+g4tOgnc=" \
    -H "Content-Type: application/json" \
    -d '{"id": "ba70ad8b-a564-4e58-9a3b-224ac0f0153f", "ts": 1585838578, "data": "1234567890"}' \
    -i \
    -o -
  ```

- direct data hash injection:
  ```console
  curl localhost:8080/ba70ad8b-a564-4e58-9a3b-224ac0f0153f/cbor/hash \
    -H "X-Auth-Token: IM+NW4iz3YtTBZyHnW+RtnArBXEK7eKy0do+g4tOgnc=" \
    -H "Content-Type: text/plain" \
    -d "VCxVx/SrzNLpKFarKDUO1HJh6vwxq8uD1/w/8Qm7hQs=" \
    -i \
    -o -
  ```

## Configuration

The identity attributes are set through a file "`identities.json`".

```json
[
  {
    "tenant": "<tenant-name>",
    "category": "<category-name>",
    "poc": "<PoC-name>",
    "uuid": "<uuid>",
    "token": "<auth token>"
  },
  ...
]
```

See example: [example_identities.json](main/example_identities.json)

It is mandatory to set a 32 byte secret for aes256 encryption of private keys (pkcs#8)
either in a file `config.json` or as an environment variable.

- File-based Configuration

  `config.json`:

    ```json
    {
      "secret32": "<base64 encoded 32 byte secret>"
    }
    ```

- Environment-based Configuration

    ```shell
    UBIRCH_SECRET32=<base64 encoded 32 byte secret>
    ```

## Optional Configurations

### Set the UBIRCH backend environment

The `env` configuration refers to the UBIRCH backend environment. The default value is `prod`, which is the production
environment. For development, the environment may be set to `demo`, which is a test system that works like the
production environment, but stores data only in a blockchain test net. __However, we suggest using `prod` in general as
`demo` may not always be available__.

> Note that the UUIDs must be registered at the according UBIRCH backend environment,
> i.e. https://console.demo.ubirch.com/.

To switch to the `demo` backend environment

- add the following key-value pair to your `config.json`:
    ```json
      "env": "demo"
    ```
- or set the following environment variable:
    ```shell
    UBIRCH_ENV=demo
    ```

### Set TCP address

You can specify the TCP address for the server to listen on, in the form `host:port`. If empty, port 8080 is used.

- add the following key-value pair to your `config.json`:
    ```json
      "TCP_addr": ":8080",
    ```
- or set the following environment variable:
    ```shell
    UBIRCH_TCP_ADDR=:8080
    ```

### Enable TLS (serve HTTPS)

1. Create a self-signed TLS certificate

   In order to serve HTTPS endpoints, you can run the following command to create a self-signed certificate with
   openssl. With this command it will be valid for ten years.
    ```console
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -nodes -out cert.pem -days 3650
    ```

2. Enable TLS in configuration

    - add the following key-value pair to your `config.json`:
        ```json
          "TLS": true
        ```
    - or set the following environment variable:
        ```shell
        UBIRCH_TLS=true
         ```

3. Set path and filename (optional)

   By default, client will look for the `key.pem` and `cert.pem` files in the working directory
   (same location as the config file), but it is possible to define a different location (relative to the working
   directory) and/or filename by adding them to your configuration file.

    - add the following key-value pairs to your `config.json`:
        ```json
          "TLSCertFile": "<path/to/TLS-cert-filename>",
          "TLSKeyFile": "<path/to/TLS-key-filename>"
        ```
    - or set the following environment variables:
        ```shell
        UBIRCH_TLS_CERTFILE=certs/cert.pem
        UBIRCH_TLS_KEYFILE=certs/key.pem
        ```

### Customize X.509 Certificate Signing Requests

The client creates X.509 Certificate Signing Requests (*CSRs*) for the public keys of the devices it is managing. The *
Common Name* of the CSR subject is the UUID associated with the public key. The values for the *Organization* and *
Country* of the CSR subject can be set through the configuration.

- add the following key-value pairs to your `config.json`:
    ```json
      "CSR_country": "<CSR Subject Country Name (2 letter code)>",
      "CSR_organization": "<CSR Subject Organization Name (e.g. company)>"
    ```
- or set the following environment variables:
    ```shell
    UBIRCH_CSR_COUNTRY=<CSR Subject Country Name (2 letter code)>
    UBIRCH_CSR_ORGANIZATION=<CSR Subject Organization Name (e.g. company)>
    ```

### Extended Debug Output

To set the logging level to `debug` and so enable extended debug output,

- add the following key-value pair to your `config.json`:
    ```json
      "debug": true
    ```
- or set the following environment variable:
    ```shell
    UBIRCH_DEBUG=true
    ```

### Log Format

By default, the log of the client is in JSON format. To change it to a (more human-eye-friendly) text format,

- add the following key-value pairs to your `config.json`:
    ```json
      "logTextFormat": true
    ```
- or set the following environment variables:
    ```shell
    UBIRCH_LOGTEXTFORMAT=true
    ```


## Copyright

```fundamental
Copyright (c) 2021 ubirch GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
