def parse_raw(file):
    with open(file) as f:
        raw = f.read()

    lines = raw.splitlines()
    method, path, _ = lines[0].split()

    headers = {}
    body = ""
    parsing_headers = True

    for line in lines[1:]:
        if not line.strip():
            parsing_headers = False
            continue

        if parsing_headers:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        else:
            body += line

    url = f"https://{headers['Host']}{path}"

    return method, url, headers, body