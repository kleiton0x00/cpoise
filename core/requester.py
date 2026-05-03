from core.useragents import get_random_ua

import random
import string
import httpx

class Requester:
    def __init__(self, proxy=None, verify=True, timeout=10):
        self.verify = verify
        self.timeout = timeout

        self.client = httpx.Client(
            http2=True,
            verify=self.verify,
            timeout=self.timeout,
            proxy=proxy
        )

    def send(self, method, url, headers=None, data=None, random_ua=True, cache_buster=None):
        try:
            headers = headers.copy() if headers else {}

            # Set a Random User-Agent
            if random_ua:
                headers["User-Agent"] = get_random_ua()

            sep = "&" if "?" in url else "?"
            full_url = None
            cb_val   = None
            cb_key   = None

            if cache_buster is None:
                # Generate random Cache buster
                cb_key = ''.join(random.choices(string.ascii_lowercase, k=6))
                cb_val = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                full_url = f"{url}{sep}{cb_key}={cb_val}"
            
            elif cache_buster is False:
                full_url = f"{url}"
                
            else:
                full_url = f"{url}?{cache_buster}"

            r = self.client.request(
                method,
                full_url,
                headers=headers,
                content=data
            )

            #print(r.http_version)

            return r, f"{cb_key}={cb_val}"

        except Exception as e:
            print(f"[CRITICAL] Request error: {e}")
            return None, None