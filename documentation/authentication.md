# Signing in

Three shapes, set with `GCR_AUTH_MODE`.

| Mode | What happens |
|---|---|
| `local` | username, password and a six digit code |
| `oidc` | your identity provider only, no local passwords |
| `both` | either one |

`both` is the one you want while you are moving people over. It is also the
one that saves you when the provider is down, because a local admin can still
get in.

## Local accounts

On first boot the app makes one admin and prints the password to the log,
once.

```bash
docker compose logs | grep -A3 'FIRST ADMIN'
```

Signing in has two stages. The password gets you a session that can reach
exactly one page, and that page asks for your code. That half session lasts
five minutes and can do nothing else.

Setting up two step draws a QR code inline, so nothing is fetched from anywhere
while you are looking at a secret. You get ten recovery codes afterward, shown
once, because only their hashes are kept. Each one works once.

Five wrong passwords locks the account for fifteen minutes. Both numbers are
settings.

## Single sign on

Standard OpenID Connect, authorization code flow with PKCE. Anything that
publishes a discovery document works: Okta, Entra, Keycloak, Google.

```bash
GCR_AUTH_MODE=both
GCR_OIDC_ISSUER=https://your-org.okta.com
GCR_OIDC_CLIENT_ID=...
GCR_OIDC_CLIENT_SECRET=...
GCR_OIDC_REDIRECT_URL=https://gcr.example.com/auth/callback
GCR_OIDC_GROUP_CLAIM=groups
GCR_OIDC_ADMIN_GROUPS=gcr-admins
GCR_OIDC_DEVELOPER_GROUPS=gcr-developers
GCR_OIDC_READER_GROUPS=gcr-readers
```

Register `GCR_OIDC_REDIRECT_URL` with your provider as an allowed redirect. It
has to match exactly.

### Groups decide the role

Every sign in re-reads your groups, so somebody moved out of the admin group
loses admin the next time they sign in rather than whenever anybody gets around
to it.

Most access wins. Somebody in both the admin group and the reader group is an
admin.

Somebody in none of the mapped groups gets no account at all. That is
deliberate. A provider that suddenly stops sending the groups claim should lock
people out rather than quietly hand everybody a default role.

There is no TOTP prompt after an OIDC sign in. Your provider already did that
part, and asking again would be theater.

### What gets checked

The id_token is verified against the provider's published keys, and so are the
issuer and the audience. Decoding a token without verifying it is one line
shorter and means anybody can hand us a token they wrote themselves saying they
are an admin.

Refused, and there are tests for each one:

- a token that has expired
- a token issued for a different application
- a token from an issuer we do not trust
- a token signed with the wrong key
- a token with no signature at all
- a callback carrying a state we never issued

PKCE means a stolen authorization code is no use to somebody who does not also
hold the verifier.

### Name collisions

If a local account already owns the username your provider sends, the sign in
is refused rather than quietly turning a password account into an SSO one. An
admin has to rename or remove one of them.

## Sessions

Twelve hours, or sixty minutes idle, whichever comes first. Both are settings.

The token is random and only its hash is stored, so somebody who reads the
database still cannot sign in as anybody.
