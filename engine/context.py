from core.utils import add_cache_buster
from core.logger import Logger

class ScanContext:
    def __init__(self, method="GET", url=None, headers=None, body=None, requester=None):
        self.log = Logger()
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.req = requester

        # baseline
        self.base_resp = None
        self.base_status = None
        self.base_len = None

    def reset(self):
        self.base_resp = None
        self.base_status = None
        self.base_len = None

    def get_busted_url(self):
        return add_cache_buster(self.url)
    
    def is_different(self, resp):
        """
        Compare response with baseline
        """
        if resp is None:
            return False

        return (
            resp.status_code != self.base_status
            or len(resp.text) != self.base_len
        )