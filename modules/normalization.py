import urllib.parse
from core.cache import extract_cache_headers
import core.config

class NormalizationAttack:

    name = "Path normalization"

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        parsed = urllib.parse.urlparse(ctx.url)
        original_path = parsed.path

        replacements = [
            (".", "%2E"),
            ("-", "%2D"),
            ("$", "%24"),
            ("*", "%2A"),
            (";", "%3B"),
            ("/", "\\")
        ]

        variants = []

        # Only add variant if replacement actually changes something
        for old, new in replacements:
            if old in original_path:
                modified = original_path.replace(old, new)
                if modified != original_path:
                    variants.append(modified)

        # No valid variants, skip module
        if not variants:
            ctx.log.error("No normalization candidates found in path")
            return

        for v in variants:
            base_url = f"{parsed.scheme}://{parsed.netloc}{v}"
            ctx.log.info(f"[*] Testing: {base_url}")

            # Use modified URL
            resp, cb = ctx.req.send(ctx.method, base_url, ctx.headers, ctx.body)

            if resp is None:
                continue

            if ctx.is_different(resp):
                cache = extract_cache_headers(resp)
                if cache is not None:
                    # Send the same request one more time to save the cache
                    _, _ = ctx.req.send(ctx.method, base_url, ctx.headers, ctx.body, True, cb)
                    ctx.log.vuln(f"Path normalization | variant={v} | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")
                    return

        ctx.log.error("Not vulnerable")