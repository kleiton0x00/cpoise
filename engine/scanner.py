from core.cache import extract_cache_headers
import core.config

# Importing attack modules
from modules.useragent import UserAgentAttack
from modules.normalization import NormalizationAttack
from modules.blind import BlindAttack
from modules.common_headers import CommonHeadersAttack
from modules.hho import HHOAttack
from modules.hmc import HMCAttack
from modules.unkeyed_headers import UnkeyedHeadersAttack
from modules.method_override import MethodOverrideAttack
from modules.unkeyed_port import UnkeyedPortAttack
from modules.long_param_dos import LongParamDoS
from modules.host_case import HostCaseNormalization
from modules.fat_get import FatGetAttack

class Scanner:

    def __init__(self):
        self.modules = [
            UserAgentAttack(),
            NormalizationAttack(),
            BlindAttack(),
            CommonHeadersAttack(),
            HHOAttack(),
            HMCAttack(),
            UnkeyedHeadersAttack(),
            MethodOverrideAttack(),
            UnkeyedPortAttack(),
            LongParamDoS(),
            HostCaseNormalization(),
            FatGetAttack(),
        ]

    def run(self, ctx):  
        if not(ctx.url.startswith("http://") or ctx.url.startswith("https://")):
            ctx.log.info("No HTTP prefix found on URL. Setting HTTPS prefix.")
            ctx.url = "https://" + ctx.url

        if core.config.cache_deception:
            ctx.log.info("Performing cache deception attack...")
            resp, _ = ctx.req.send(ctx.method, ctx.url, ctx.headers, ctx.body, True, False)

            # Store baseline in context (for comparison with upcoming requests from various attacking modules)
            ctx.base_resp = resp
            ctx.base_status = resp.status_code
            ctx.base_len = len(resp.text)

            # Run the cache_deception attack module
            try:
                import modules.cache_deception
                modules.cache_deception.CacheDeceptionAttack().run(ctx)
            except Exception as e:
                ctx.log.critical(f"Error on loading the module: {e}")        
        
        elif (core.config.scan_all or core.config.cache_dos):
            # First detect for any presence of Cache header
            ctx.log.info("Performing initial cache detection...")
            resp, cb = ctx.req.send(ctx.method, ctx.url, ctx.headers, ctx.body)
            
            if resp is None:
                ctx.log.critical("Failed to get baseline response. Exiting.")
                return
            
            cache_status = extract_cache_headers(resp)

            # stop if no cache detected
            if cache_status is None:
                ctx.log.error("No cache indicators detected.")
                if core.config.continue_on_fail:
                    pass
                if core.config.skip_on_fail:
                    return
                else:
                    ctx.log.info("Do you still want to continue the scan? [y/n]: ")
                    scan_continue = input("> ").strip()
                    if scan_continue.lower() == "y":
                        pass
                    else:
                        return
            
            # Store baseline in context (for comparison with upcoming requests from various attacking modules)
            ctx.base_resp = resp
            ctx.base_status = resp.status_code
            ctx.base_len = len(resp.text)
            
            # Extract Cache headers for later fuzzing and store in context (important for modules)
            x_headers = extract_cache_headers(resp)
            ctx.cache_status = cache_status
            ctx.x_headers = x_headers

            if x_headers:
                ctx.log.debug(f"Discovered Cache headers: {', '.join(x_headers)}")

            ctx.log.info("Starting modules...")

            for m in self.modules:
                try:
                    m.run(ctx)
                except Exception as e:
                    ctx.log.critical(f"Module error ({m.name}): {e}")

            # Running only the cache deception attack module
            if core.config.scan_all:
                ctx.log.info("Performing cache deception attack...")
                resp, cb = ctx.req.send(ctx.method, ctx.url, ctx.headers, ctx.body)

                # Store baseline in context (for comparison with upcoming requests from various attacking modules)
                ctx.base_resp = resp
                ctx.base_status = resp.status_code
                ctx.base_len = len(resp.text)

                # Run the cache_deception attack module
                try:
                    import modules.cache_deception
                    modules.cache_deception.CacheDeceptionAttack().run(ctx)
                except Exception as e:
                    ctx.log.critical(f"Error on loading the module: {e}")