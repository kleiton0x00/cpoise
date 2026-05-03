from core.cache import extract_cache_headers
import core.config

class HostCaseNormalization:
    name = "Host Header Case Normalization"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        headers = ctx.headers.copy()

        host = headers.get("Host") or headers.get("host")

        if not host:
            ctx.log.error("No Host header found")
            return

        headers["Host"] = host.upper()

        resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        if resp is None:
            return

        if ctx.is_different(resp):
            if extract_cache_headers(resp):
                _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)
                ctx.log.vuln(f"Host case normalization issue | Exploit PoC: {ctx.url}?{cb}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                return

        ctx.log.error("Not vulnerable")