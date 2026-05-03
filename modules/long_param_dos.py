from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random
import string
from core.cache import extract_cache_headers
import core.config

class LongParamDoS:
    name = "Long Parameter Value DoS"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        parsed = urlparse(ctx.url)
        qs = parse_qs(parsed.query)

        if not qs:
            ctx.log.error("No GET or POST parameters found")
            return

        for param in qs.keys():

            long_value = ''.join(random.choices(string.ascii_letters, k=2048))

            new_qs = qs.copy()
            new_qs[param] = [long_value]

            new_query = urlencode(new_qs, doseq=True)

            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))

            resp, cb = ctx.req.send(ctx.method, test_url, ctx.headers, ctx.body)

            if resp is None:
                continue

            if ctx.is_different(resp):
                if extract_cache_headers(resp):
                    # Send the same request one more time to save the cache
                    _, _ = ctx.req.send(ctx.method, test_url, ctx.headers, ctx.body, True, cb)
                    ctx.log.vuln(f"Long parameter DoS | param={param} | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")

                    return

        ctx.log.error("Not vulnerable")