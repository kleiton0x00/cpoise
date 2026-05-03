from core.cache import extract_cache_headers
import core.config
import urllib.parse
import re


class CacheDeceptionAttack:
    name = "Cache Deception"

    # Arbitrary segments to test
    SEGMENTS = ['/', '\\', '=', '?', '&', ';', ':', '#']

    # Extensions to test
    EXTENSIONS = [
        ".css", ".js", ".jpeg", ".jpg",
        ".png", ".ico", ".webp"
    ]

    def run(self, ctx):
        
        vuln = False
        
        ctx.log.debug(f"Testing for {self.name}")

        parsed = urllib.parse.urlparse(ctx.url)

        # Baseline request
        base_resp, _ = ctx.req.send(ctx.method, ctx.url, ctx.headers, ctx.body, True, False)
        if not base_resp:
            ctx.log.error("Baseline request failed")
            return

        base_body = base_resp.text
        base_path = parsed.path.rstrip("/")

        ctx.log.info("Initializing the basic fuzzing (segment fuzzing)")
        if self._test_paths(ctx, parsed, base_path):
            vuln = True
            if core.config.continue_on_success:
                pass
            else:
                return

        ctx.log.info("Initializing smart fuzzing with extracted JS paths")
        js_paths = self._extract_js_paths(base_body)

        if not js_paths:
            ctx.log.error("No dynamic JavaScript path could be parsed.")
            return

        for js_path in js_paths:

            parts = [p for p in js_path.strip("/").split("/") if p]
            traversal = "../" * len(parts)
            traversal_enc = "..%2F" * len(parts)
            traversal_double = "..%252F" * len(parts)

            parts_base = [p for p in base_path.strip("/").split("/") if p]
            traversal_base = "../" * len(parts_base)
            traversal_enc_base = "..%2F" * len(parts_base)
            traversal_double_base = "..%252F" * len(parts_base)

            variants = [
                f"{js_path.rstrip('/')}/{traversal}{base_path[1:]}",
                f"{js_path.rstrip('/')}/{traversal_enc}{base_path[1:]}",
                f"{js_path.rstrip('/')}/{traversal_double}{base_path[1:]}",
                f"{base_path.rstrip('/')}/{traversal_base}{js_path[1:]}",
                f"{base_path.rstrip('/')}/{traversal_enc_base}{js_path[1:]}",
                f"{base_path.rstrip('/')}/{traversal_double_base}{js_path[1:]}",
            ]

            for variant in variants:
                ctx.log.info("Testing: " + variant)
                if self._test_paths(ctx, parsed, variant):
                    vuln = True
                    if core.config.continue_on_success:
                        pass
                    else:
                        return
            
            for seg in self.SEGMENTS:
                # Variants with various segments (encoded and normal)
                traversal = str(seg) + "/" + "../" * len(parts)
                traversal_enc = urllib.parse.quote(seg) + "%2F" + "%2E%2E%2F" * len(parts)
                
                traversal_base = str(seg) + "/" + "../" * len(parts_base)
                traversal_enc_base = urllib.parse.quote(seg) + "%2F" + "%2E%2E%2F" * len(parts_base)
                
                variants = [
                    f"{js_path.rstrip('/')}{traversal}{base_path[1:]}",
                    f"{js_path.rstrip('/')}{traversal_enc}{base_path[1:]}",
                    f"{base_path.rstrip('/')}{traversal_base}{js_path[1:]}",
                    f"{base_path.rstrip('/')}{traversal_enc_base}{js_path[1:]}",
                ]

                for variant in variants: 
                    ctx.log.info("Testing: " + variant)
                    if self._test_paths(ctx, parsed, variant):
                        vuln = True
                        if core.config.continue_on_success:
                            pass
                        else:
                            return

        if vuln == False:
            ctx.log.error("No Cache Deception vulnerability found")


    def _test_paths(self, ctx, parsed, base_path):
        found = False

        # variants that do NOT depend on ext
        for seg in self.SEGMENTS:
            encoded_seg = urllib.parse.quote(seg)

            variants = [
                f"{base_path}{seg}abc",
                f"{base_path}{encoded_seg}abc",
            ]

            for path in variants:
                if self._send_and_check(ctx, parsed, path):
                    found = True
                    if not core.config.continue_on_success:
                        return True

        # variants that DO depend on ext
        for ext in self.EXTENSIONS:
            new_path = f"{base_path}{ext}"
            if self._send_and_check(ctx, parsed, new_path):
                found = True
                if not core.config.continue_on_success:
                    return True

            for seg in self.SEGMENTS:
                encoded_seg = urllib.parse.quote(seg)

                variants = [
                    f"{base_path}{seg}abc{ext}",
                    f"{base_path}{encoded_seg}abc{ext}",
                ]

                for path in variants:
                    if self._send_and_check(ctx, parsed, path):
                        found = True
                        if not core.config.continue_on_success:
                            return True

        return found


    def _send_and_check(self, ctx, parsed, path):
        """
        Sends request and evaluates cache deception conditions
        """

        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        resp, _ = ctx.req.send(ctx.method, new_url, ctx.headers, ctx.body, True, False)

        if not resp:
            return False

        # MUST match baseline exactly (body + status)
        if not ctx.is_different(resp):
            if extract_cache_headers(resp):
                ctx.log.vuln(f"Cache Deception | {new_url}")

                if core.config.open_browser:
                    import webbrowser
                    webbrowser.open_new_tab(new_url)

                return True

        return False


    def _extract_js_paths(self, html):
        """
        Extracts JS paths and expands them into all parent directories
        """
        paths = set()

        matches = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE
        )

        for src in matches:
            parsed = urllib.parse.urlparse(src)
            path = parsed.path

            if not path:
                continue

            # Split path and remove filename
            parts = path.strip("/").split("/")[:-1]

            # Build all directory levels
            for i in range(1, len(parts) + 1):
                directory = "/" + "/".join(parts[:i])
                paths.add(directory)

        return paths