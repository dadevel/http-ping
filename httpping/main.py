from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import base64
import hashlib
import itertools
import json
import re
import sys

from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
import urllib3

from spnego import NTLMHash
from spnego._ntlm_raw.messages import Challenge
from spnego._spnego import unpack_token
import spnego

session = Session()
session.verify = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# HttpNtlmAuth provides no argument to pass in a NT hash.
# Instead we have to monkey-patch 'spnego.client'.

original_client = spnego.client

def monkey_client(username: str, password: str, *args, **kwargs):
    return original_client([NTLMHash(username, None, password)], password=None, *args, **kwargs)

spnego.client = monkey_client


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('--threads', type=int, default=1, metavar='UINT')
    entrypoint.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6356.209 Safari/537.36', metavar='STRING')
    group = entrypoint.add_argument_group('auth')
    group.add_argument('-d', '--domain', default='')
    group.add_argument('-u', '--username', default='')
    group = group.add_mutually_exclusive_group()
    group.add_argument('-p', '--password', default='')
    group.add_argument('-H', '--hash', default='')
    entrypoint.add_argument('targets', nargs='*', metavar='URL')
    opts = entrypoint.parse_args()

    session.headers['User-Agent'] = opts.user_agent
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        targets = opts.targets if opts.targets else (line.rstrip() for line in sys.stdin)
        for result in pool.map(ping, itertools.repeat(opts), targets):
            log(**result)


def ping(opts: Namespace, target: str) -> dict[str, Any]:
    test1 = session.get(target)
    auth_methods = extract_auth_methods(test1)
    username = f'{opts.domain}\\{opts.username}' if opts.domain else opts.username
    if 'basic' in auth_methods and username:
        auth = HTTPBasicAuth(username, opts.password)
    elif 'ntlm' in auth_methods:
        nthash = opts.hash if opts.hash else hashlib.new('md4', opts.password.encode('utf-16le')).hexdigest()
        auth = HttpNtlmAuth(username, nthash, send_cbt=True)
    else:
        return make_result(target, test1, authentication=auth_methods, channel_binding=None, ntlm_info=None)
    test2 = session.get(target, auth=auth)
    ntlm_info = extract_ntlm_info(test2.history[-1]) if isinstance(auth, HttpNtlmAuth) else None
    if test2.status_code == 401 or not isinstance(auth, HttpNtlmAuth):
        return make_result(target, test2, authentication=auth_methods, channel_binding=None, ntlm_info=ntlm_info)
    # close connection to force reauthentication
    session.close()
    # retest without channel binding
    auth.send_cbt = False
    test3 = session.get(target, auth=auth)
    return make_result(target, test2, authentication=auth_methods, channel_binding=test3.status_code == 401, ntlm_info=ntlm_info)


def extract_auth_methods(response: Response) -> list[str]:
    header = response.headers.get('WWW-Authenticate', '')
    if not header:
        return []
    return header.lower().split(', ')


def extract_ntlm_info(response: Response) -> dict[str, str]:
    header = response.headers.get('WWW-Authenticate', '')
    if not header.startswith('NTLM '):
        return {}
    message = base64.b64decode(header.removeprefix('NTLM '))
    token = unpack_token(message, unwrap=True)
    if not isinstance(token, Challenge):
        return {}
    result = {}
    if token.version:
        result.update(name=token.target_name, version=f'{token.version.major}.{token.version.minor}.{token.version.build}')
    if token.target_info:
        result.update({k.name: v for k, v in token.target_info.items() if k.name not in ('timestamp', 'eol')})
    return result


TITLE_PATTERN = re.compile(b'<title>([^<>]+)</title>', re.IGNORECASE)

def extract_title(response: Response) -> str:
    match = TITLE_PATTERN.search(response.content)
    if not match:
        return ''
    return match.group(1).decode('utf-8', errors='surrogateescape')


def make_result(target: str, response: Response, **kwargs: Any) -> dict[str, Any]:
    return dict(
        url=target,
        status_code=response.status_code,
        reason=response.reason,
        server=response.headers.get('Server', ''),
        content_type=response.headers.get('Content-Type', '').lower().split(';')[0],
        headers={k.lower(): v for k, v in response.headers.items()},
        size=len(response.content),
        title=extract_title(response),
        **kwargs,
    )


def log(**kwargs: Any) -> None:
    print(json.dumps(kwargs, separators=(',', ':')))


if __name__ == '__main__':
    main()
