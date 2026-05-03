from core.cache import extract_cache_headers
import core.config

class FatGetAttack:
    name = "Fat GET"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        headers = ctx.headers.copy()

        # Force body on GET request
        body = "xyz"

        headers["Content-Length"] = str(len(body))

        resp, cb = ctx.req.send(
            ctx.method,
            ctx.url,
            headers,
            body
        )

        if resp is None:
            return

        if ctx.is_different(resp):
            if extract_cache_headers(resp):
                # Send the same request one more time to save the cache
                resp, cb = ctx.req.send(
                    ctx.method,
                    ctx.url,
                    headers,
                    body,
                    True,
                    cb
                )
                
                ctx.log.vuln(f"Fat GET behavior detected | Exploit PoC: {ctx.url}?{cb}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                return

        ctx.log.error("Not vulnerable")