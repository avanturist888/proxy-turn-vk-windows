# Code signing policy

Windows releases of this fork are built from source by GitHub Actions
(`.github/workflows/release.yml`) from a tagged commit of this repository
and are signed through SignPath.

Free code signing provided by [SignPath.io](https://signpath.io),
certificate by [SignPath Foundation](https://signpath.org).

## What is signed

Only artifacts produced by the release workflow of this repository:

- `wdtt.exe` — the desktop application;
- `cli\wdtt.exe` — the console utility;
- `wdtt-setup-windows-amd64.exe` — the installer.

Nothing built outside this repository's CI is signed. Each release lists
SHA-256 checksums of its files in `SHA256SUMS.txt`.

## Team roles

- Committers and reviewers: [avanturist888](https://github.com/avanturist888)
- Approvers (sign-off for each release signing request):
  [avanturist888](https://github.com/avanturist888)

All team members use multi-factor authentication for GitHub and SignPath.

## Privacy

The program connects only to what it needs to work, or to what the user
configures:

- VK API and VK TURN relays, to obtain relay credentials and carry the tunnel;
- the tunnel servers the user adds;
- the GitHub Releases API of this repository, to check for a newer version.

It does not send telemetry or usage data anywhere. Logs and settings stay on
the user's computer (`%APPDATA%\wdtt`).
