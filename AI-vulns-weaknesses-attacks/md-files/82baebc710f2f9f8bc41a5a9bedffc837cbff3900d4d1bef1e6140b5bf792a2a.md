3/7/24, 3:11 PM CWE - CWE-836: Use of Password Hash Instead of Password for Authentication (4.14)
https://cwe.mitre.org/data/deﬁnitions/836.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-836: Use of Password Hash Instead of Password for Authentication
Weakness ID: 836
Vulnerability Mapping: 
View customized information:
 Description
The product records password hashes in a data store, receives a hash of a password from a client, and compares the supplied hash
to the hash obtained from the data store.
 Extended Description
Some authentication mechanisms rely on the client to generate the hash for a password, possibly to reduce load on the server or
avoid sending the password across the network. However , when the client is used to generate the hash, an attacker can bypass the
authentication by obtaining a copy of the hash, e.g. by using SQL injection to compromise a database of authentication credentials, or
by exploiting an information exposure. The attacker could then use a modified client to replay the stolen hash without having
knowledge of the original password.
As a result, the server-side comparison against a client-side hash does not provide any more security than the use of passwords
without hashing.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 1390 Weak Authentication
PeerOf 602 Client-Side Enforcement of Server-Side Security
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 1211 Authentication Errors
 Relevant to the view "Architectural Concepts" (CWE-1008)
 Modes Of Introduction
Phase Note
Implementation REALIZA TION: This weakness is caused during implementation of an architectural security tactic.
 Applicable Platforms
Languages
Class: Not Language-Specific (Undetermined Prevalence)
 Common Consequences
Scope Impact Likelihood
Access ControlTechnical Impact: Bypass Protection Mechanism; Gain Privileges or Assume Identity
An attacker could bypass the authentication routine without knowing the original password.
 Observed Examples
Reference Description
CVE-2009-1283 Product performs authentication with user-supplied password hashes that can be obtained from a
separate SQL injection vulnerability (CVE-2009-1282).
CVE-2005-3435 Product allows attackers to bypass authentication by obtaining the password hash for another user and
specifying the hash in the pwd argument.
 Memberships
Nature Type ID Name
MemberOf 1396 Comprehensive Categorization: Access Control
 Vulnerability Mapping NotesAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:11 PM CWE - CWE-836: Use of Password Hash Instead of Password for Authentication (4.14)
https://cwe.mitre.org/data/deﬁnitions/836.html 2/2Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID Attack Pattern Name
CAPEC-644 Use of Captured Hashes (Pass The Hash)
CAPEC-652 Use of Known Kerberos Credentials
 Content History
 Submissions
Submission Date Submitter Organization
2011-03-22
(CWE 1.12, 2011-03-30)CWE Content Team MITRE
 Modifications