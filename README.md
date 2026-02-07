# vault-yubikey-login

Simple CLI to authenticate to HashiCorp Vault using a YubiKey PIV certificate. The [TLS certificates auth method](https://developer.hashicorp.com/vault/docs/auth/cert) is used for this purpose. After successful login, the vault token is stored in `~/.vault-token` and can now be used with the [vault cli](https://developer.hashicorp.com/vault/docs/commands). I am not aware of any way to use the YubiKey together with the vault cli.

Build
-----

Install Go (1.20+ recommended) and build:

```sh
go build -o vault-yubiky-login cmd/vault-yubikey-login/main.go
```

Usage
-----
- `vault-yubikey-login cert [certRole]`: Authenticate with a YubiKey certificate. If a certificate role name `certRole` not specified, the auth method will try to authenticate against all trusted certificates.

Environment variables
---------------------

- `VAULT_ADDR` (required): Vault server address, e.g. `https://vault.example.com:8200`.
- `VAULT_CACERT` (optional): Path to CA certificate PEM file. If not set, system root CAs are used.

Example with Test system (not for production!)
--------

In this example, the cli tool `ykman` is used to configure the yubikey.

Create file `client-cert-extensions.cnf` with content
```sh
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

Execute the following commands:
```sh
# yubikey key generation and csr creation
ykman piv keys generate --algorithm ECCP256 9a pubkey.pem
ykman piv certificates request --subject "CN=USER_NAME" 9a pubkey.pem user.csr

-----
# creating locale CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -noenc -keyout ca.key -out ca.crt -subj "/CN=localhost"  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# sign user csr
openssl x509 -req -in user.csr -out client.crt -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -extfile client-cert-extensions.cnf

# import user cert on yubikey
ykman piv certificates import 9a client.crt

# cert prüfen
ykman piv info

# start dev vault server (in a new tab)
vault server -dev -dev-root-token-id=root -dev-tls -dev-tls-cert-dir=./

# configure tls auth, ca.crt = trusted CA
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='.//vault-ca.pem'
vault auth enable cert
vault write auth/cert/certs/web display_name=web policies=web,prod certificate=@ca.crt ttl=3600

# login
./vault-yubikey-login cert my-role
```

What it does
------------

- Reads certificate and private key from the YubiKey PIV slot.
- Sends a TLS client-cert login request to Vault at `$VAULT_ADDR/v1/auth/cert/login` with JSON `{"name": "<certRole>"}`.
- On success extracts `auth.client_token` from the Vault response and writes it to `~/.vault-token` with permissions `0600`.


Notes
-----

- The tool requires access to a YubiKey and the PIN to unlock the authentication slot.
- Errors are printed to stderr and the program exits with non-zero status on failure.

License
-------

See the project `LICENSE` file.
