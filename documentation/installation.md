# Installation

## Before you start

You need docker with the compose plugin, and a user that can talk to the docker
daemon.  That is the whole list.  Everything else lives in the image.

You also need a way for the tool to read your GitHub repositories.  See
[Auth, and why Okta matters](../README.md#1-auth-and-why-okta-matters), and do
that part first if you can, since the installer asks for it.

## The short way

```bash
git clone https://your.git.server/github-code-review
cd github-code-review
./install.sh
```

The installer asks where to listen, how people sign in, how to reach GitHub and
where the reports go.  Then it writes `.env`, builds the image and starts it.
It waits for the health check rather than telling you it worked and hoping.

Run it again any time.  It reads your existing `.env` and offers what is
already there, so you can change one answer without retyping the rest.

## The manual way

```bash
cp .env.example .env
$EDITOR .env
docker compose up -d
```

## First sign in

When the auth mode is `local` or `both`, the first boot makes an admin account
and prints the password to the log exactly once.

```bash
docker compose logs | grep -A3 'FIRST ADMIN'
```

Sign in with it, and the app makes you change it and set up TOTP before you can
reach anything else.  Write the recovery codes down somewhere that is not the
laptop you just set them up on.

When the mode is `oidc`, there is no local admin at all.  The first person to
sign in from a group you mapped to admin becomes one.

## Where things end up

| Path | What it holds | Survives a compose down |
|---|---|---|
| `gcr-db` volume | the SQLite database | yes |
| `gcr-cache` volume | grype database, CISA and EPSS feeds | yes |
| `/data/docker/github-code-review/reports` | the two report files | yes, it is a bind mount |

The reports directory is a bind mount on purpose, so whatever ingests the
findings can read it straight off the host without going through docker.

## Putting TLS in front

It listens on loopback by default and speaks plain HTTP.  Put nginx or caddy in
front of it and terminate TLS there.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Then set `GCR_TRUSTED_PROXIES` to the proxy address, or the rate limiter will
see every request as coming from the same place and the login lockout will
apply to everyone at once.

## Upgrading

```bash
git pull
docker compose build
docker compose up -d
```

The database migrates itself on boot.  Nothing is dropped, and new columns get
sane defaults.  Take a copy of the volume first if you like:

```bash
docker run --rm -v gcr-db:/db -v "$PWD:/out" ubuntu:26.04 \
  tar czf /out/gcr-db-backup.tar.gz -C /db .
```

## Uninstalling

```bash
docker compose down          # keeps the database and the reports
docker compose down -v       # removes the volumes as well, this is the real one
```

The reports directory is a bind mount on the host, so `down -v` does not touch
it.  Delete that yourself if you actually want it gone.

## The database

It lives in a docker volume called `gcr-db`, and the container makes it the
first time it starts. There is nothing to set up.

```
docker compose up -d     # empty volume, database created, admin made
docker compose down      # container gone, volume stays
docker compose up -d     # same database, same users, same findings
```

`docker compose down -v` is the one that takes the volume with it. That is the
only way to lose the database by accident, and it asks for the `-v`.

### Upgrades

A release that adds a column brings it in on the next start. The app compares
what the code expects against what the file has and adds anything missing. It
only ever adds, so an upgrade cannot drop a column or rewrite your data.

Take a copy first if you want one:

```bash
docker run --rm -v gcr-db:/db -v "$PWD:/out" ubuntu:26.04 \
  tar czf /out/gcr-db-backup.tar.gz -C /db .
```

### Where it is on disk

Inside the container: `/data/docker/github-code-review/db/gcr.sqlite3`

On the host: wherever docker keeps the `gcr-db` volume, which
`docker volume inspect gcr-db` will tell you.

The file is mode 600 and owned by the container user. It holds password
hashes, session hashes and every finding, so it is not something to leave
world readable.
