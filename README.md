# http-ping

## Setup

Install with [pipx](https://github.com/pypa/pipx/).

~~~ bash
pipx install git+https://github.com/dadevel/http-ping.git
~~~

## Usage

Unauthenticated request to single endpoint with NTLM authentication.

~~~ bash
http-ping https://mail.corp.com/rpc/ | tee -a ./http-ping.json | jq
~~~

~~~ json
{
  "url": "https://mail.corp.com/rpc/",
  "status_code": 401,
  "reason": "Unauthorized",
  "server": "Microsoft-IIS/10.0",
  "content_type": "",
  "headers": {
    "content-length": "0",
    "connection": "keep-alive",
    "keep-alive": "timeout=40",
    "server": "Microsoft-IIS/10.0",
    "request-id": "28a3add7-84c4-4bd0-b64b-52304610df44",
    "x-owa-version": "15.2.1544.14",
    "www-authenticate": "Negotiate, NTLM",
    "date": "Sat, 22 Feb 2025 22:30:16 GMT",
    "strict-transport-security": "max-age=31536000; includeSubDomains"
  },
  "size": 0,
  "title": "",
  "authentication": [
    "negotiate",
    "ntlm"
  ],
  "channel_binding": null,
  "ntlm_info": {
    "name": "CORP",
    "version": "10.0.17763",
    "nb_domain_name": "CORP",
    "nb_computer_name": "EXCH01",
    "dns_domain_name": "corp.local",
    "dns_computer_name": "exch01.corp.local",
    "dns_tree_name": "corp.local"
  }
}
~~~

Check multiple endpoints and filter on TLS Channel Binding support.
Requires valid credentials.

~~~ bash
cat ./urls.txt | http-ping -d corp.local -u jdoe -H b9f917853e3dbf6e6831ecce60725930 | tee -a ./http-ping.json | jq -c 'select(.channel_binding == false)'
~~~

> Currently testing Channel Binding is only possible with NTLM authentication.
> Kerberos support could be added with [requests-kerberos](https://github.com/requests/requests-kerberos).

