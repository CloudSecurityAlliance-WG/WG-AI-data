3/7/24, 2:56 PM CWE - CWE-318: Cleartext Storage of Sensitive Information in Executable (4.14)
https://cwe.mitre.org/data/deﬁnitions/318.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-318: Cleartext Storage of Sensitive Information in Executable
Weakness ID: 318
Vulnerability Mapping: 
View customized information:
 Description
The product stores sensitive information in cleartext in an executable.
 Extended Description
Attackers can reverse engineer binary code to obtain secret data. This is especially easy when the cleartext is plain ASCII. Even if the
information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then
decode the information.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 312 Cleartext Storage of Sensitive Information
 Relevant to the view "Architectural Concepts" (CWE-1008)
 Modes Of Introduction
Phase Note
Implementation
 Applicable Platforms
Languages
Class: Not Language-Specific (Undetermined Prevalence)
 Common Consequences
Scope Impact Likelihood
ConfidentialityTechnical Impact: Read Application Data
 Observed Examples
Reference Description
CVE-2005-1794 Product stores RSA private key in a DLL and uses it to sign a certificate, allowing spoofing of servers
and Adversary-in-the-Middle (AITM) attacks.
CVE-2001-1527 administration passwords in cleartext in executable
 Memberships
Nature Type ID Name
MemberOf 963 SFP Secondary Cluster: Exposed Data
MemberOf 1402 Comprehensive Categorization: Encryption
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the V ariant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Variant
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 2:56 PM CWE - CWE-318: Cleartext Storage of Sensitive Information in Executable (4.14)
https://cwe.mitre.org/data/deﬁnitions/318.html 2/2
 Notes
Terminology
Different people use "cleartext" and "plaintext" to mean the same thing: the lack of encryption. However , within cryptography , these
have more precise meanings. Plaintext is the information just before it is fed into a cryptographic algorithm, including already-
encrypted text. Cleartext is any information that is unencrypted, although it might be in an encoded form that is not easily human-
readable (such as base64 encoding).
 Taxonomy Mappings
Mapped T axonomy Name Node ID Fit Mapped Node Name
PLOVER Plaintext Storage in Executable
 Related Attack Patterns
CAPEC-ID Attack Pattern Name
CAPEC-37 Retrieve Embedded Sensitive Data
CAPEC-65 Sniff Application Code
 Content History
 Submissions
Submission Date Submitter Organization
2006-07-19
(CWE Draft 3, 2006-07-19)PLOVER
 Modifications
 Previous Entry Names