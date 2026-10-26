# IP Triage Lab

An offline Python utility that validates and classifies IPv4 and IPv6 addresses for the first step of a SecOps investigation.

**Status:** runnable CLI lab, initialized on 2026-10-26. The repository's historical name is `ip-checker-api`; an HTTP API and threat intelligence integrations are not implemented.

## Why this exists

Before sending an address to an enrichment provider, establish what it represents and whether disclosure is permitted. This tool performs no DNS, HTTP, WHOIS, reputation lookup or scanning. It has no API key and no external dependency. Classification does not establish maliciousness, ownership or exploitability.

## Run

Python 3.11 or newer:

```sh
git clone https://github.com/Xilambila/ip-triage-lab.git
cd ip-triage-lab
python ip_triage.py 192.0.2.10
python ip_triage.py 2001:db8::10
python -m unittest discover -s tests -v
```

Example output:

```json
{
  "address": "192.0.2.10",
  "version": 4,
  "scope": "documentation",
  "assessment": "not-performed",
  "network_queries": 0
}
```

Invalid input returns exit code 2 and a generic error without echoing the input. Successful output contains the submitted address: keep operational output private and use documentation addresses when sharing examples.

## Classification and limits

Documentation networks are matched explicitly, before Python's broader address properties. RFC 1918 and IPv6 unique-local ranges are classified as `private`. Other categories include loopback, link-local, unspecified, multicast, special-use and global-unicast. IPv4-mapped IPv6 is identified separately with its embedded IPv4 classification; callers should not silently treat it as a separate public identity.

Subnets, zone identifiers and hostnames are rejected. Remaining address properties come from Python's `ipaddress` module and can differ between Python releases. This is a triage aid, not an exhaustive routing database or a network allow/deny policy engine.

## Investigation workflow

1. Preserve the original event in the authorized evidence store.
2. Validate and classify the address locally.
3. Correlate identity, asset ownership, timestamps and observed behavior.
4. Enrich externally only where policy permits, with approved providers and minimum data.
5. Document confidence and alternative explanations before recommending containment.

See the [synthetic investigation case](https://github.com/Xilambila/Xilambila/tree/main/showcases/incident-response) for an example of evidence, hypotheses and response decisions. It is a tabletop exercise, not a production incident.

## Structure

```text
ip_triage.py                 Standard library CLI
tests/test_ip_triage.py      Address edge cases and CLI behavior
SECURITY.md                 Disclosure and data handling
```

## References

- [Python ipaddress](https://docs.python.org/3/library/ipaddress.html)
- [RFC 5737: IPv4 addresses for documentation](https://www.rfc-editor.org/rfc/rfc5737)
- [RFC 3849: IPv6 documentation prefix](https://www.rfc-editor.org/rfc/rfc3849)
