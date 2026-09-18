# Contributing

Contributions should keep SentinelUSB small, understandable, and defensive.

Before submitting changes:

- Prefer standard Linux utilities and established security libraries.
- Do not add unnecessary desktop or development dependencies to the live image.
- Do not include live malware samples.
- Keep target-system access read-only unless a feature explicitly requires an opt-in write operation.
- Add tests for scanner behavior where practical.
- Document dependencies that materially affect ISO size.

For detection rules, include the source, license, and reason for inclusion.
