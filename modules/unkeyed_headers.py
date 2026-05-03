import random
import string
from core.cache import extract_cache_headers
import core.config

class UnkeyedHeadersAttack:
    name = "Unkeyed Headers"

    HEADERS = [
        "capitalized host header",
        "x-forwarded-proto",
        "x-http-method-override",
        "x-amz-website-redirect-location",
        "authorization",
        "x-rewrite-url",
        "x-original-host",
        "x-forwarded-prefix",
        "x-amz-server-side-encryption",
        "trailer",
        "fastly-ssl",
        "fastly-host",
        "fastly-ff",
        "fastly-client-ip",
        "content-type",
        "api-version",
        "acunetix-header",
        "accept-version",
        "x-timer",
    ]

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        # Extract Cache headers from response that the server already uses
        dynamic_headers = extract_cache_headers(ctx.base_resp) or []

        all_headers = self.HEADERS + dynamic_headers

        for h in all_headers:
            headers = ctx.headers.copy()
            headers[h] = ''.join(random.choices(string.ascii_letters, k=8))

            resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

            if resp and ctx.is_different(resp):
                if extract_cache_headers(resp):
                    # Send the same request one more time to save the cache
                    _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)

                    ctx.log.vuln(f"Unkeyed header {h} | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                    return

        ctx.log.error("Not vulnerable")