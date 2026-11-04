# ADR 0008: GitHub Is the Only Contact Channel

Status: Accepted (2026-10-13); recorded 2026-10-14. Where stated: EULA section 11, SECURITY.md, PRIVACY.md section 10, README.

## Decision
OpenVAPT publishes no email address, postal address, phone number, chat or form. Bugs and ideas go to GitHub Issues, questions to GitHub Discussions, security flaws to GitHub Private Vulnerability Reporting, and notices from the project are given by posting on the repository. CI tests that the website publishes no email address.

## Reason
The project collects no data and runs no server-side code, so a form or mailbox would be its first data flow and its first personal-data store. One channel, hosted by a third party with its own privacy statement, keeps the zero-data position true, keeps the owner's identity unpublished (a High risk the owner accepted) and gives every exchange a public, dated record that both sides can cite.

## Consequences
People without a GitHub account cannot report a flaw privately. Whether to add a second, non-GitHub path (for example a published key and a one-way address that is read but never answered) or to confirm GitHub as the only channel is an owner decision still open on 2026-10-14; SECURITY.md says so. Until then, security.txt (RFC 9116) points to the GitHub reporting page and this policy. The project is also fully dependent on GitHub's availability for contact, which EULA section 25 (force majeure) covers.
