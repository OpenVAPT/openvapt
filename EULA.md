# End User Licence Agreement

Version 1.1, effective 2026-10-13. This agreement is a draft pending review by a Malaysian advocate and solicitor. Please read it in full; it is written to be plain, honest and complete.

This End User Licence Agreement ("Agreement") applies to everyone who downloads, builds, installs, copies or uses OpenVAPT, including its source code, compiled programs, documentation and this website (together, the "Software"). By doing any of these things you agree to this Agreement. If you do not agree, do not download or use the Software.

## 1. Who We Are

"We", "us" and "the developers" mean The OpenVAPT Project and every person who has written or contributed to the Software. "You" means the individual, and any organisation on whose behalf that individual acts, who downloads or uses the Software.

## 2. Academic Purpose

The Software is an academic project made for learning and open review. It demonstrates how a vulnerability assessment tool can be designed, built and tested. It is not a product, not a service, and not professional security advice.

## 3. Acknowledgement and Acceptance

OpenVAPT is **academic, non-commercial, open-source code, free to download and use, for your own personal or business use, 100% at your own risk**. You may not sell it and you may not use it to provide services.

Before downloading, and again before every scan, you must read, study, understand, acknowledge, agree to and accept each of the following statements. By downloading, building, installing or using the Software you confirm every one of them:

1. I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy and the Licence.
2. I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.
3. I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or for which I have the owner's permission.
4. I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.
5. I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.
6. I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.
7. I agree that the developers and contributors provide OpenVAPT as is, without any warranty, and accept no responsibility or liability of any kind, to the fullest extent the law allows.
8. I am solely responsible for complying with all laws that apply to me, including the Computer Crimes Act 1997 and the Cyber Security Act 2024 in Malaysia, and the laws of my own country.

The website asks you to tick each statement before showing the download instructions, and the tool asks you to type `I ACCEPT` before every scan. Neither stores or sends your answer anywhere.

## 4. Licence

The Software is licensed to you under the PolyForm Noncommercial License 1.0.0 together with the OpenVAPT Additional Permission (see the Licence page). In summary:

1. **Anyone may use it.** Individuals, students, educational institutions, government bodies and companies may download and use the Software free of charge.
2. **Own machines, own use.** You may run the Software only on computers and servers that you own or control, for your own use.
3. **No services and no business.** You may not use the Software to provide services to anyone else, whether paid or unpaid, and you may not sell it, rent it, include it in a product or service, or use it in any other business activity that earns money from it.

If this Agreement and the licence texts differ, the stricter restriction applies to commercial use, and the licence texts govern your copyright rights.

## 5. Authorisation and Lawful Use

1. You must have the legal right to run the Software on the machine where you run it. If the machine belongs to your employer or another person, you must have their permission before running the Software.
2. You are solely responsible for complying with every law that applies to you, including, in Malaysia, the Computer Crimes Act 1997, the Cyber Security Act 2024, the Personal Data Protection Act 2010 and the Communications and Multimedia Act 1998, and equivalent laws in your own country.
3. The Software is designed to examine only the machine it runs on. You must not modify it, or use any part of it, to examine, access or attack any system you are not authorised to examine.

## 6. What the Software Does on Your Machine

So that you can decide with full information, this is everything the Software does when you run a scan:

1. It reads configuration and system information on the machine it runs on, which may include sensitive files such as `/etc/passwd`, `/etc/shadow` (when run as root), sudo rules, SSH and web server configuration, kernel parameters and package lists.
2. It runs a fixed list of read-only commands, including `sshd -T`, `apt-get -s upgrade` (simulation only), `dnf` or `yum updateinfo`, firewall status commands, `systemctl is-active`, `php -v` and `php -r` limited to reading configuration values. You can see the full list in the source code and preview every action with `openvapt scan --dry-run`.
3. It sends ordinary HTTP GET requests and TLS handshakes to the websites and services on the same machine, only through 127.0.0.1, including requests for a short list of fixed paths such as `/.git/HEAD`, `/.env` and `/phpinfo.php` to see whether they are exposed. These requests may appear in your web server logs and may trigger your security tools.
4. It does not change, delete, install, restart, exploit, attack or brute-force anything, and it makes no connection to any other machine.
5. It uses CPU, memory and disk time while it runs. Each check has a time limit and work is bounded, but on a busy or fragile server even read-only activity can have side effects.
6. It writes a report, which describes weaknesses of your machine, to a folder you choose, readable only by your user account. Secrets are redacted by pattern matching, which may not catch everything. Protecting and sharing the report is your responsibility.
7. If you enable signing (the default), it creates a private key on your machine at `~/.config/openvapt/report-key`. Keep it private.

## 7. How OpenVAPT Is Made

OpenVAPT is developed by the project owner with substantial help from AI coding assistants. To date its design, code, tests, documentation, website and these legal drafts were produced by Claude (by Anthropic, used through Claude Code) under the owner's direction and review. AI-produced work can contain mistakes, including security mistakes. The full source code, test suite and history are public so that anyone can review them. Commits made with AI assistance carry a `Co-Authored-By` line.

## 8. Third-Party Components

The compiled program contains only OpenVAPT's own code and the Go standard library (BSD 3-Clause licence). The website additionally uses self-hosted copies of AG Grid Community (MIT), Apache ECharts (Apache-2.0), Lucide icons (ISC) and the IBM Plex fonts (SIL Open Font License 1.1). Their licences are listed in `THIRD_PARTY_NOTICES.md` and apply to those components.

## 9. The Operator and Notices

The person who runs the project currently chooses not to be named publicly. The project has no email contact. Questions, notices and reports may be raised publicly in GitHub Discussions or Issues at github.com/OpenVAPT/openvapt, and security flaws privately through GitHub Private Vulnerability Reporting.

## 10. Your Risk, 100%

1. **You use the Software entirely at your own risk.** You alone decide whether to download, run or rely on it, and you alone bear every consequence.
2. The Software performs automated, read-only checks. It may still behave unexpectedly, consume resources, produce wrong results, or miss weaknesses. You should test it on a non-production system first and keep backups.
3. Results are not proof that a system is secure or insecure. Every decision you take based on the Software or its reports is your own responsibility.

## 11. No Warranty

To the fullest extent permitted by law, the Software is provided "as is" and "as available", with all faults, and without any warranty, guarantee, condition or representation of any kind, whether express, implied or statutory, including any warranty of merchantability, quality, fitness for a particular purpose, accuracy, completeness, security, availability, non-infringement, or that the Software will be free of errors, defects or harmful components.

## 12. No Liability

1. To the fullest extent permitted by law, the developers shall not be liable to you or to anyone else for any loss or damage of any kind arising from or connected with the Software, this website or this Agreement, however caused and under any legal theory (including contract, tort, negligence, breach of statutory duty or otherwise), even if advised of the possibility of such loss or damage.
2. This includes, without limitation, direct, indirect, incidental, special, consequential, exemplary or punitive damages; loss of data, profits, revenue, business, goodwill or reputation; system downtime or damage; security incidents or breaches; vulnerabilities that were not detected; regulatory penalties; and claims by third parties.
3. Where the law does not allow liability to be excluded entirely, the total liability of the developers for all claims together is limited to zero Malaysian Ringgit, or, if that limit is not enforceable, to RM1 (one Malaysian Ringgit), which reflects that the Software is provided free of charge.
4. Nothing in this Agreement excludes liability that cannot be excluded by law, such as liability for fraud.

## 13. Indemnity

You agree to indemnify and hold harmless the developers from and against any claim, demand, loss, damage, penalty, cost or expense (including reasonable legal fees) made by any third party or authority arising from your download or use of the Software, your breach of this Agreement, or your breach of any law or the rights of any other person.

## 14. No Support and No Obligation

The developers have no obligation to provide support, maintenance, updates, fixes or answers. Any help given in public GitHub discussions is voluntary and given without liability.

## 15. No Data Collection

The Software does not send any data to the developers or anyone else, and this website collects no data. See the Privacy Policy.

## 16. Export and Sanctions

You are responsible for complying with export control and sanctions laws that apply to you, including Malaysia's Strategic Trade Act 2010. The Software contains detection logic only and no exploit or intrusion code.

## 17. Termination

Your rights under this Agreement end automatically if you breach it, subject to the cure period in the licence. On termination you must stop using and delete the Software. Sections 3 and 10 to 13 and 18 survive termination.

## 18. Governing Law

This Agreement is governed by the laws of Malaysia. The courts of Malaysia have exclusive jurisdiction over any dispute, unless the law of your country requires otherwise.

## 19. Changes

We may update this Agreement. Each version is dated and kept in the public Git history. The version in force when you download a copy of the Software applies to that copy.

## 20. Legal Review Status

This Agreement is a draft written in good faith and is awaiting review by a Malaysian advocate and solicitor before the public launch at openvapt.com. Its wording may change; every version is dated and kept in the public Git history, and the version in force when you download a copy applies to that copy.

## 21. Whole Agreement

This Agreement, the licence texts, the Disclaimer, the Acceptable Use Policy and the Privacy Policy are the whole agreement about the Software. If any part is found unenforceable, the rest remains in force and the unenforceable part is applied to the greatest extent allowed.
