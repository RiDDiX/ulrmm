# Security Policy

## Reporting a vulnerability

Report security issues privately through GitHub private vulnerability
reporting: open the Security tab of the affected repository and choose "Report
a vulnerability", or go to
https://github.com/RiDDiX/ulrmm/security/advisories/new.
Do not open a public issue for a security report.

Include the affected version, what an attacker can do and the steps to
reproduce it. Leave out passwords, tokens, keys and data of other people.

## Supported versions

Security fixes, if any, are made only for the latest release of the server,
the dashboard, the agent and the script library. Update first and check that
the problem is still there.

## Scope

- In scope: the code in the four UniversalLocal RMM repositories, ulrmm,
  ulrmm-web, ulrmm-agent and ulrmm-scripts.
- Out of scope: third-party software that UniversalLocal RMM installs or uses,
  such as MeshCentral, RustDesk, NATS, nginx, PostgreSQL or Redis; report
  those to their projects. Installations run by someone else are out of scope
  too.
- Test only against an installation you run yourself. Do not access systems or
  data that are not yours, and do not disrupt other people's services.

## What to expect

There is no bug bounty and no promised response or fix time. Reports are read
and handled as time allows. If a fix is made, it ships in a normal release and
is named in the changelog.
