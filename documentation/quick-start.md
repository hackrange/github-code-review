# Quick start

One line. It clones the project and walks you through the rest.

```bash
curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
```

You need `git` and `docker` with the compose plugin, and a user that can talk
to the docker daemon. That is the whole list.

## What it asks

Six questions, all with sensible defaults. Press enter to take them.

1. **Where it listens.** Loopback and port 8080 by default. Put a reverse proxy
   in front for TLS.
2. **How people sign in.** Local with two step, your identity provider, or
   both.
3. **Identity provider details**, only if you picked one of those.
4. **GitHub access.** A token, or a GitHub App if you are behind SSO.
5. **Where the reports go.** `/data/docker/github-code-review/reports` unless
   you say otherwise.

Then it builds the image, starts the container, waits for the health check, and
prints your sign in details:

```
  +--------------------------------------------------------------+
  |  SIGN IN WITH THIS                                           |
  +--------------------------------------------------------------+
     username:  admin
     password:  a-long-random-one-goes-here
  +--------------------------------------------------------------+
```

That password is generated on first boot and written to one file inside the
database volume, mode 600. The app deletes it once that account has changed its
password and set up two step.

If you miss it:

```bash
docker compose exec github-code-review \
  cat /data/docker/github-code-review/db/first-admin.txt
```

## First sign in

You will be asked to change the password and set up two step before you can
reach anything. Save the recovery codes somewhere that is not the laptop you
just set them up on.

## Running it again

Safe. It reads your existing `.env` and offers what is already there, so you
can change one answer without retyping the rest.

```bash
cd /data/docker/github-code-review
./install.sh
```

## Somewhere other than the default

```bash
GCR_DIR=/srv/gcr curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
```

## Updating

```bash
cd /data/docker/github-code-review
git pull
docker compose build && docker compose up -d
```

Or just run the one liner again. It pulls and rebuilds if the project is
already there.

## Getting rid of it

```bash
docker compose down       # keeps the database and the reports
docker compose down -v    # takes the volumes too
```

The reports directory is a bind mount on the host, so `down -v` leaves it
alone. Delete that yourself if you want it gone.
