CACHE_KEYWORDS = [
    "ETag", 
    "Last-Modified", 
    "Cache-Control", 
    "X-Cache-Status", 
    "Vary", 
    "X-Cache", 
    "CF-Cache-Status", 
    "X-Amz-Cf-Id", 
    "X-Fastly-Cache",
    "X-Vercel-Cache",
    "X-Vercel-Id",
    "X-Proxy-Cache",
    "X-Cache-Hits",
    "X-Varnish",
    "X-Check-Cacheable",
    "X-Cache-Lookup",
    "X-Hcdn-Cache-Status"
]

PREVENT_CACHE_KEYWORDS = [
    "private",
    "no-store",
    "no-cache",
    "post-check=0",
    "pre-check=0",
    "max-age=0",
    "bypass",
    "expired",
    "stale",
    "revalidated",
    "dynamic",
    "pass",
    "nocache",
    "denied",
    "refresh",
    "error from cloudfront",
    "0, 0"
]

def extract_cache_headers(resp):
    if resp is None:
        return None
    
    cache_headers = []

    for k, v in resp.headers.items():
        val = f"{k}:{v}".lower()
        #print(val)
        
        for keyword in CACHE_KEYWORDS:
            if keyword.lower() in val.lower() or keyword.lower == "age":
                for negate_keyword in PREVENT_CACHE_KEYWORDS:
                    if negate_keyword in v.lower():
                        print(f"[DEBUG] Server does not enfore cache. Reason: {val}")
                        return None
                    
                #print(f"{k}:{v}")
                cache_headers.append(k)

     # remove duplicates
    if cache_headers:
        return list(set(cache_headers))
    
    return None

def is_cache_hit(resp):
    """
    return True if cache is HIT
    return False if cache is MISS
    return None if no cache at all 
    """
    
    if resp is None:
        return None
    
    for k, v in resp.headers.items():
        if v.lower().startswith("hit"):
            return True
        if v.lower().startswith("miss"):
            return False
        
        # Fallback: Age header (weak signal)
        if "age" in resp.headers:
            try:
                age = int(resp.headers["age"])
                if age > 0:
                    return True
                else:
                    return False
            except ValueError:
                return None
    
    # this means that the response is probably not caching at all
    return None
