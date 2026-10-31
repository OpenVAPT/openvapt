# Scope and Authorisation Gate

The gate exists because assessing a computer without permission is a crime in most countries (for example the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act 1990 in the United Kingdom, the Computer Crimes Act 1997 in Malaysia, and laws implementing the Budapest Convention elsewhere). It also keeps the work inside OpenVAPT's licence: own use only, no services to others.

## Questions to Ask Before Anything Runs

1. "Which machine are we assessing, and am I running commands on that machine itself?"
2. "Do you own or control this machine? If it belongs to your employer, have they authorised you in writing to assess it?"
3. "Is it production, staging or a lab? When is a quiet time to run the scan?"
4. "Should I ask before every fix, or do you want to approve a list of fixes up front?"

## Proceed Only When

- The commands run on the machine being assessed (confirm with `hostname` and `uname -a`).
- The user states ownership or control, or written employer authorisation, in their own words.
- The work is for the user's own use, not for a client, customer or third party.

## Stop When

- The user wants to assess another host, an IP range, a domain or a website from this machine.
- The machine belongs to a client, customer, friend, school (without written authorisation) or "a target".
- The user asks for exploitation, password cracking, phishing, evasion, persistence or anything in Rule 4.
- The user wants the assessment sold or delivered as a service.

Say what the problem is in one sentence, and offer the alternative: run the skill on their own machine, get written authorisation, or engage an authorised penetration tester.

## Scope Record (put at the top of your log and the report)

```
Machine:        <hostname> (<OS and version>)
Assessed from:  the machine itself, loopback only
Owner/control:  <user's statement, verbatim>
Environment:    production | staging | lab
Date and time:  <UTC>
Fix approval:   per change | approved list: <ids>
Out of scope:   other hosts, exploitation, application logic testing
```
