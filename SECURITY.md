# Security policy

## Reporting a vulnerability

**Don't open a public issue for a security problem.** Report it privately through the repository's
**Security** tab: choose **Report a vulnerability**, which opens a private GitHub security advisory. Include:

- what the problem is and where it is (file and function, or endpoint)
- the steps to reproduce it, or a proof of concept
- what an attacker could do with it

You'll get a reply within 7 days. Please give us a reasonable time to fix it before you disclose it.

## In scope

- **Server-side request forgery** through `resolve_url_redirects` or any other network call. Examples:
  reaching private, loopback or link-local addresses, cloud metadata endpoints, or non-HTTP schemes.
- **Prompt injection** that makes the agent:
  - call a tool it shouldn't
  - leak its instructions
  - avoid the verdict floor
- **Ways to make a known-bad link come back `likely_legitimate`**, in either engine.
- API abuse that gets around the rate limit, the session limits or the message size limit.
- Pasted messages ending up in logs, storage or error responses.
- Cross-site scripting in the web UI, especially from text in a pasted message.

## Out of scope

- Scams the checker doesn't catch. Please report those as a [wrong verdict](../../issues/new?template=wrong_verdict.yml) instead.
- The known DNS-rebinding race window in the redirect resolver, which is documented in the README.
- Problems in third-party services the tools query, such as RDAP, WHOIS or Safe Browsing.

## Supported versions

Only the latest commit on `main` gets security fixes.
