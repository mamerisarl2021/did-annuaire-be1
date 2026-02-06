<!-- This is an auto-generated reply by CodeRabbit -->
> 💡 **TIP**
> For best results, initiate chat on the files or code changes.

`@daviddee`

Recommended setup using /app/data/dids/.well-known with a shared volume

1) Docker Compose changes (add a shared volume and mount it in both containers)
- Define a new named volume (dids_volume).
- Mount it RW in annuaire-backend at /app/data/dids.
- Mount it RO in nginx at the same path /app/data/dids.
- Expose DIDS_ROOT in the backend env (or .env.backend).

compose.yml snippets to apply:
- services.nginx.volumes: add
  - dids_volume:/app/data/dids:ro
- services.annuaire-backend.environment (or .env.backend): add
  - DIDS_ROOT=/app/data/dids/.well-known
- services.annuaire-backend.volumes: add
  - dids_volume:/app/data/dids
- volumes: add
  dids_volume:

Example (only the deltas shown):
services:
  nginx:
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - static_volume:/static:ro
      - media_volume:/media:ro
      - dids_volume:/app/data/dids:ro   # NEW

  annuaire-backend:
    environment:
      - DIDS_ROOT=/app/data/dids/.well-known    # NEW (or put in .env.backend)
    volumes:
      - static_volume:/app/staticfiles
      - media_volume:/app/mediafiles
      - dids_volume:/app/data/dids              # NEW

volumes:
  postgres_data:
  rabbitmq_data:
  static_volume:
  media_volume:
  dids_volume:                                   # NEW

2) Nginx config change (serve did.json from the shared volume)
Replace the did.json location block with this (only the block):

location ~ ^/([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)/([^/]+)/did\.json$ {
    root /app/data/dids/.well-known;
    try_files $uri =404;

    default_type application/did+json;
    add_header Access-Control-Allow-Origin "*" always;
    add_header Cache-Control "public, max-age=300";
    add_header X-DID-Env "PROD";
    limit_except GET HEAD { deny all; }
}

Why this works
- Django writes to /app/data/dids/.well-known/{org}/{user}/{type}/did.json inside the backend container.
- The named volume mirrors that path into the nginx container at the same in-container path /app/data/dids/.well-known, so Nginx can read it.
- root + try_files $uri =404 resolves to /app/data/dids/.well-known/<org>/<user>/<type>/did.json.

3) Restart and verify
- Recreate containers after editing compose.yml and nginx.conf:
  - docker compose up -d nginx annuaire-backend
  - docker compose logs -f nginx annuaire-backend
- Inside the backend container, confirm the env and path:
  - printenv DIDS_ROOT  → should be /app/data/dids/.well-known
  - ls -la /app/data/dids/.well-known  → should list org/user folders after a publish.
- Re-publish a DID (POST /api/registry/dids/{did}/publish) and confirm:
  - File appears at /app/data/dids/.well-known/{org}/{user}/{type}/did.json inside the nginx container:
    docker exec -it annuaire-nginx ls -la /app/data/dids/.well-known/{org}/{user}/{type}/
  - HTTP GET https://annuairedid-fe.qcdigitalhub.com/{org}/{user}/{type}/did.json returns 200 with application/did+json.

Notes
- Your backend runs as user: "0" (root) in the compose; it has write permissions on the mounted volume by default. If you later drop privileges to a non-root UID/GID, ensure the volume is owned/granted to that UID.
- Keep DID_DOMAIN_HOST set to annuairedid-fe.qcdigitalhub.com so the internal DID matches the served host.

That’s all you need. If you want me to also provide a small health check endpoint (e.g., GET /api/diagnostics/publish-root) that returns the current DIDS_ROOT and filesystem writability to help ops, I can add that too.