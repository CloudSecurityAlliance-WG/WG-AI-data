3/7/24, 3:02 PM CWE - CWE-523: Unprotected Transport of Credentials (4.14)
https://cwe.mitre.org/data/deﬁnitions/523.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-523: Unprotected T ransport of Credentials
Weakness ID: 523
Vulnerability Mapping: 
View customized information:
 Description
Login pages do not use adequate measures to protect the user name and password while they are in transit from the client to the
server .
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 522 Insuf ficiently Protected Credentials
CanAlsoBe 312 Cleartext Storage of Sensitive Information
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 255 Credentials Management Errors
 Relevant to the view "Architectural Concepts" (CWE-1008)
 Background Details
SSL (Secure Socket Layer) provides data confidentiality and integrity to HTTP . By encrypting HTTP messages, SSL protects from
attackers eavesdropping or altering message contents.
 Modes Of Introduction
Phase Note
Architecture and DesignOMISSION: This weakness is caused by missing a security tactic during the architecture and design
phase.
 Common Consequences
Scope Impact Likelihood
Access ControlTechnical Impact: Gain Privileges or Assume Identity
 Potential Mitigations
Phases: Operation; System Configuration
Enforce SSL use for the login page or any page used to transmit user credentials or other sensitive information. Even if the
entire site does not use SSL, it MUST use SSL for login. Additionally , to help prevent phishing attacks, make sure that SSL
serves the login page. SSL allows the user to verify the identity of the server to which they are connecting. If the SSL serves
login page, the user can be certain they are talking to the proper end system. A phishing attack would typically redirect a user to
a site that does not have a valid trusted server certificate issued from an authorized supplier .
 Detection Methods
Automated Static Analysis
Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this
weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically , this is done by building a
model of data flow and control flow , then searching for potentially-vulnerable patterns that connect "sources" (origins of input)
with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)
Effectiveness: High
 Memberships
Nature Type ID Name
MemberOf 930 OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
MemberOf 963 SFP Secondary Cluster: Exposed DataAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:02 PM CWE - CWE-523: Unprotected Transport of Credentials (4.14)
https://cwe.mitre.org/data/deﬁnitions/523.html 2/2MemberOf 1028 OWASP Top Ten 2017 Category A2 - Broken Authentication
MemberOf 1346 OWASP Top Ten 2021 Category A02:2021 - Cryptographic Failures
MemberOf 1396 Comprehensive Categorization: Access Control
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 Taxonomy Mappings
Mapped T axonomy Name Node ID Fit Mapped Node Name
Software Fault Patterns SFP23 Exposed Data
 Related Attack Patterns
CAPEC-ID Attack Pattern Name
CAPEC-102 Session Sidejacking
 Content History
 Submissions
Submission Date Submitter Organization
2006-07-19
(CWE Draft 3, 2006-07-19)Anonymous Tool V endor (under NDA)
 Modifications
