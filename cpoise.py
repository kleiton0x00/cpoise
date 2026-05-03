import argparse
from core.requester import Requester
from core.parser import parse_raw
import core.config
from engine.context import ScanContext
from engine.scanner import Scanner

banner = """                  _          
  ___ _ __   ___ (_)___  ___ 
 / __| '_ \\ / _ \\| / __|/ _ \\
| (__| |_) | (_) | \\__ \\  __/
 \\___| .__/ \\___/|_|___/\\___|
     |_|         
                \033[1;31m@kleiton0x7e\033[0m            
"""

def load_targets(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        return []

def main():
    print(banner)

    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="Target URL (must have HTTP prefix)")
    parser.add_argument("-r", "--request", help="File containing the raw HTTP request")
    parser.add_argument("-p", "--proxy", help="Proxy URL (must have HTTP prefix. E.g: 'http://127.0.0.1:8080')")
    parser.add_argument("-f", "--file", help="File containing list of URLs")
    parser.add_argument("-k", "--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--collaborator", help="Collaborator URL used for OOB interaction")
    parser.add_argument("-b", "--open-browser", action="store_true", help="Open the exploit PoC automatically to a default browser once found the vulnerability")
    parser.add_argument("--continue-on-fail", action="store_true", help="Continue scanning automatically even if no evidence of caching is found")
    parser.add_argument("--continue-on-success", action="store_true", help="Continue scanning even if a vulnerability has been found")
    parser.add_argument("--skip-on-fail", action="store_true", help="Skip the vulnerability scanning on the host when there is no evidence of caching")
    # scan modes
    parser.add_argument("-d", "--cache-deception", action="store_true", help="Scan only for Cache Deception vulnerability")
    parser.add_argument("-c", "--cache-dos", action="store_true", help="Scan only for Cache Poisoned DoS vulnerability")
    parser.add_argument("-a", "--all", action="store_true", help="Scan everything: Cache Poisoned DoS and Cache Deception")
    args = parser.parse_args()
    
    ctx = ScanContext()
    ctx.log.info("Starting CPoise scanner")

    if args.collaborator:
        # Set global variable
        core.config.collaborator = args.collaborator

    if args.open_browser:
        # Set global variable
        core.config.open_browser = True

    if args.cache_deception:
        # Set global variable
        core.config.cache_deception = True

    if args.cache_dos:
        # Set global variable
        core.config.cache_dos = True

    if args.skip_on_fail:
        # Set global variable
        core.config.skip_on_fail = True

    if args.all:
        # Set global variable
        core.config.scan_all = True

    if args.continue_on_fail:
        # Set global variable
        core.config.continue_on_fail = True

    if args.continue_on_success:
        core.config.continue_on_success = True

    if (args.file and args.request) or (args.file and args.url) or (args.url and args.request) or not(args.file or args.request or args.url):
        ctx.log.error("Use either -u, -r or -f")
        return
    
    if (args.cache_deception and args.all):
        ctx.log.error("Cannot use both scanning mode")
        return
    
    if (args.cache_deception and args.all) or (args.cache_deception and args.cache_dos) or (args.cache_dos and args.all) or not (args.cache_dos or args.all or args.cache_deception):
        ctx.log.error("Choose one scanning mode: -a, -c or -d")
        return

    # Init requester
    ctx.req = Requester(
        proxy=args.proxy if args.proxy else None,
        verify=not args.no_verify,
        timeout=args.timeout
    )

    scanner = Scanner()

    # ---------------------------
    # RAW HTTP REQUEST MODE
    # ---------------------------
    if args.request:
        method, url, headers, body = parse_raw(args.request)

        ctx.method = method
        ctx.url = url
        ctx.headers = headers
        ctx.body = body

        try:
            scanner.run(ctx)
        except Exception as e:
            ctx.log.critical(f"Scan failed for {url}: {e}")
    
    # ---------------------------
    # MASS SCAN MODE
    # ---------------------------
    if args.file:
        targets = load_targets(args.file)

        if not targets:
            ctx.log.error("No valid targets found")
            return

        ctx.log.info(f"Loaded {len(targets)} targets")

        for i, url in enumerate(targets, 1):
            print("")
            ctx.log.info(f"[{i}/{len(targets)}] Scanning {url}")

            ctx.url = url
            ctx.method = "GET"
            ctx.headers = {}
            ctx.body = None

            try:
                scanner.run(ctx)
            except Exception as e:
                ctx.log.critical(f"Scan failed for {url}: {e}")

    # ---------------------------
    # SINGLE TARGET MODE
    # ---------------------------
    else:
        if args.url:
            ctx.url = args.url
            ctx.method = "GET"
            ctx.headers = {}
            ctx.body = None

            try:
                scanner.run(ctx)
            except Exception as e:
                ctx.log.critical(f"Scan failed for {url}: {e}")

    ctx.log.success("Scan completed")

if __name__ == "__main__":
    main()