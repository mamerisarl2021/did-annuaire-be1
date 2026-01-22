from config.env import env

CORS_URLS_REGEX = r"^/api/.*$"
CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_ORIGINS = []
ENV_CORS_ALLOWED_ORIGINS = env.str("CORS_ALLOWED_ORIGINS", default="")
for origin in ENV_CORS_ALLOWED_ORIGINS.split(","):
    CORS_ALLOWED_ORIGINS.append(f"{origin}".strip().lower())