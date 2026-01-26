from django.core.cache import cache

from ninja import Body
from ninja_extra import api_controller, route
from ninja_jwt.authentication import JWTAuth
from ninja_jwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from ninja_jwt.tokens import RefreshToken

from src.core.apis import BaseAPIController


@api_controller("/auth", tags=["Auth"], auth=JWTAuth())
class LogoutController(BaseAPIController):
    @route.post("/logout")
    def logout(self, request, body: dict = Body(...)):
        """
        Body:
          - refresh?: string (optional when all=true)
          - all?: boolean (default false) — revoke all sessions for the user
        """
        
        rl_key = f"logout:uid:{request.user.id}"
        if cache.get(rl_key):
            return self.create_response(message="Too many requests. Try again shortly.", status_code=429)
        cache.set(rl_key, "1", timeout=120)
        
        all_flag = bool(body.get("all") or False)
        refresh = (body.get("refresh") or "").strip()

        if all_flag:
            # Revoke all refresh tokens for this user (idempotent)
            tokens = OutstandingToken.objects.filter(user=request.user)
            for t in tokens:
                BlacklistedToken.objects.get_or_create(token=t)
            return self.create_response(
                message="All sessions revoked.",
                status_code=200,
            )

        if not refresh:
            return self.create_response(
                message="Provide 'refresh' or set all=true.",
                status_code=400,
            )

        
    # Single-token revoke with ownership check
        try:
            tok = RefreshToken(refresh)
            token_user_id = str(tok.payload.get("user_id", ""))
            if token_user_id != str(request.user.id):
                return self.create_response(message="Forbidden.", status_code=403)
            tok.blacklist()  # idempotent
            return self.create_response(message="Logged out.", status_code=200)
        except Exception:
            return self.create_response(message="Invalid refresh token.", status_code=400)

