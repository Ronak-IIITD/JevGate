# Security policy

## Supported versions

Security fixes are made against the latest code on the default branch. This project is an early-stage prototype and does not currently promise production security support or a service-level response time.

## Reporting a vulnerability

Please report suspected vulnerabilities privately using GitHub's **Report a vulnerability** flow under the repository's **Security** tab. Include the affected version or commit, impact, reproduction steps, and any mitigations you identified. Avoid sending real credentials or private user data; use synthetic examples.

If private vulnerability reporting is unavailable for this repository, contact a maintainer privately using the contact information on the maintainer's GitHub profile. Please do not publish exploit details before maintainers have had a reasonable opportunity to respond.

## Deployment notes

- Treat model output as untrusted advice, not authorization.
- Keep OpenRouter and other provider credentials in server-side secret storage.
- Restrict access to the local audit database and define retention appropriate for your deployment.
- Do not expose the development dashboard or unauthenticated API to the public internet.
- Keep target-tool authorization, argument validation, and approval checks in the host application.
