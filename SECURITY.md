# Security policy

This service must remain authenticated. Do not remove `RELAY_API_KEY`, publish the key, or deploy an unauthenticated open relay.

Keep `ALLOW_ANY_PUBLIC_HOST=false` and maintain a narrow `ALLOWED_HOSTS` list whenever possible. Rotate the relay key immediately if it is exposed. Review Vercel usage and logs for unexpected traffic.

The service intentionally blocks private and local addresses, non-HTTP protocols, URL-embedded credentials, arbitrary destination ports, unsafe headers, oversized bodies, and unvalidated redirects.
