# Behind a load balancer

## The port

**8080.** Point the balancer at that.

The container always listens on 8080 inside. `GCR_PORT` is what gets published
on the host and also defaults to 8080, so unless you changed it, 8080 is the
answer on both sides.

## Three settings that matter

```bash
GCR_BIND_ADDRESS=0.0.0.0                    # or the interface the balancer uses
GCR_PORT=8080
GCR_TRUSTED_PROXIES=10.0.0.5,10.0.0.6       # your balancer addresses
GCR_FORCE_HTTPS=true
```

### It binds to loopback by default

A balancer on another host cannot reach `127.0.0.1:8080`. Change
`GCR_BIND_ADDRESS` to something it can, or narrow it to the one interface the
balancer uses.

If the balancer runs on the same host, leave it on loopback and point the
balancer at `127.0.0.1:8080`. Nothing off the box can reach it that way, which
is the safest arrangement.

### Set the trusted proxies, or lock everybody out

Every request will arrive from the balancer, so without this the rate limiter
and the failed login lockout see your whole userbase as one client. One person
mistyping their password five times would lock out everyone.

`X-Forwarded-For` is only believed when the connection came from an address in
this list. From anywhere else the header is ignored completely, so nobody can
set it themselves and walk past the limiter.

Put every address the balancer might connect from in the list. If it has both
a public and a private address and you are not sure which one the container
sees, list both. Extra entries cost nothing.

CIDR works: `GCR_TRUSTED_PROXIES=10.0.0.0/24`.

### TLS stops at the balancer

The app speaks plain HTTP. Keep `GCR_FORCE_HTTPS=true`, which marks session
cookies secure and sends HSTS, and make sure the balancer sends
`X-Forwarded-Proto: https`.

## Health checks

| Path | What it does | Use it for |
|---|---|---|
| `/healthz` | returns `ok`, no auth, no database | the balancer |
| `/readyz` | checks the database answers | your own monitoring |

Point the balancer at `/healthz`. It is deliberately cheap and does not touch
the database, so a slow query never takes the whole thing out of rotation.

`/readyz` returns 503 when the database is unhappy, which is more useful for
alerting than for load balancing.

Neither one asks who is calling, so whatever they say goes to anybody who can
reach the port. That is why they say so little. The reason a readiness check
failed is in the container log, not in the response, and neither endpoint names
the product or the release.

## One backend only

The database is SQLite in a local volume, and sessions live in it. Two
containers behind one balancer would each have their own database and their own
users, and people would be signed out at random depending on which one they
landed on.

So: point the balancer at one backend.

That is fine when the balancer is there for TLS, a stable hostname, or an
access control list. It does not work if you want two instances for redundancy
or scale. That would need a shared database and a shared session store, which
is a real change rather than a setting.

## A worked example

nginx, terminating TLS, one backend on the same host:

```nginx
upstream gcr {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name gcr.example.com;

    ssl_certificate     /etc/ssl/certs/gcr.pem;
    ssl_certificate_key /etc/ssl/private/gcr.key;

    # A restore posts the whole backup archive in one request.
    client_max_body_size 512m;
    proxy_read_timeout   900s;

    location / {
        proxy_pass http://gcr;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /healthz {
        proxy_pass http://gcr;
        access_log off;
    }
}
```

With that, the container keeps `GCR_BIND_ADDRESS=127.0.0.1` and
`GCR_TRUSTED_PROXIES=127.0.0.1`.

## Restoring a backup through the balancer

Restore is the one request that does not look like the rest of the app. It
posts the whole archive in a single POST, then rewrites every table before it
answers. Two balancer settings decide whether that works.

**`client_max_body_size` has to clear the archive.** nginx defaults to 1m,
which is smaller than most real backups, and it refuses the upload with a 413
before the app sees any of it. The app itself accepts archives up to 512m, so
match that and the balancer stops being the limit.

A browser on HTTP/2 usually reports this as a broken connection rather than a
413, because the connection is cut while the upload is still in flight.
`ERR_HTTP2_PROTOCOL_ERROR` in Chrome is the common shape.

**`proxy_read_timeout` has to outlast the restore.** The restore empties every
table before it starts inserting, so a timeout partway through leaves the
destination with nothing in it. That is a worse outcome than a refused upload.
Give it more room than you think it needs.

### If the settings look right and it still fails

Check that the balancer actually reloaded. `nginx -T` prints the configuration
as it sits on disk, not the one the running workers loaded, so a change that
never took effect still looks applied. A restart or a verified reload is the
only way to be sure.

The site's error log settles where the request died:

```
client intended to send too large body: 1806129 bytes,
    server: gcr.example.com, request: "POST /backup/restore HTTP/2.0"
```

That names the server block which made the decision and the size it refused.
If the line is there, the balancer rejected the upload and the app never saw
it. If it is not, the balancer is not where the request is dying.
