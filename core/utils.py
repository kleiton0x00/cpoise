import random
import string
import urllib.parse

def rand(n=8):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def compare(base, new):
    if not base or not new:
        return False

    return base.status_code != new.status_code or base.text != new.text

def add_cache_buster(url):
    parsed = urllib.parse.urlparse(url)

    key = rand()
    value = rand()

    query = urllib.parse.parse_qsl(parsed.query)
    query.append((key, value))

    new_query = urllib.parse.urlencode(query)

    new_url = parsed._replace(query=new_query).geturl()

    return new_url, f"{key}={value}"