"""Response policy outside authentication and request limits, including errors."""

from myf.host.config import settings

DEFAULT_CSP = b"default-src 'none'; frame-ancestors 'none'; sandbox"


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secured(message):
            if message["type"] == "http.response.start":
                policy = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"strict-origin-when-cross-origin",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-embedder-policy": b"require-corp",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"x-permitted-cross-domain-policies": b"none",
                    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
                    b"cache-control": b"no-store",
                }
                if settings.cookie_secure:
                    policy[b"strict-transport-security"] = b"max-age=31536000"
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in policy
                ]
                # API answers are data, never documents: a response that sets
                # no policy of its own gets one that runs and frames nothing.
                if not any(k.lower() == b"content-security-policy" for k, _ in headers):
                    headers.append((b"content-security-policy", DEFAULT_CSP))
                message = {**message, "headers": headers + list(policy.items())}
            await send(message)

        await self.app(scope, receive, secured)
