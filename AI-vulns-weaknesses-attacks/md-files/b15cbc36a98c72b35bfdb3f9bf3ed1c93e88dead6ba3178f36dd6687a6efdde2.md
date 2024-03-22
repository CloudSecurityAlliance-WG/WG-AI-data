3/7/24, 3:02 PM CWE - CWE-507: Trojan Horse (4.14)
https://cwe.mitre.org/data/deﬁnitions/507.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-507: T rojan Horse
Weakness ID: 507
Vulnerability Mapping: 
View customized information:
 Description
The product appears to contain benign or useful functionality , but it also contains code that is hidden from normal operation that
violates the intended security policy of the user or the system administrator .
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 506 Embedded Malicious Code
ParentOf 508 Non-Replicating Malicious Code
ParentOf 509 Replicating Malicious Code (V irus or W orm)
 Modes Of Introduction
Phase Note
Implementation
Operation
 Common Consequences
Scope Impact Likelihood
Confidentiality
Integrity
AvailabilityTechnical Impact: Execute Unauthorized Code or Commands
 Potential Mitigations
Phase: Operation
Most antivirus software scans for Trojan Horses.
Phase: Installation
Verify the integrity of the product that is being installed.
 Memberships
Nature Type ID Name
MemberOf 904 SFP Primary Cluster: Malware
MemberOf 1412 Comprehensive Categorization: Poor Coding Practices
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 Notes
TerminologyAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:02 PM CWE - CWE-507: Trojan Horse (4.14)
https://cwe.mitre.org/data/deﬁnitions/507.html 2/2Definitions of "T rojan horse" and related terms have varied widely over the years, but common usage in 2008 generally refers to
software that performs a legitimate function, but also contains malicious code.
Almost any malicious code can be called a Trojan horse, since the author of malicious code needs to disguise it somehow so that it
will be invoked by a nonmalicious user (unless the author means also to invoke the code, in which case they presumably already
possess the authorization to perform the intended sabotage). A Trojan horse that replicates itself by copying its code into other
program files (see case MA1) is commonly referred to as a virus. One that replicates itself by creating new processes or files to
contain its code, instead of modifying existing storage entities, is often called a worm. Denning provides a general discussion of
these terms; dif ferences of opinion about the term applicable to a particular flaw or its exploitations sometimes occur .
Other
Potentially malicious dynamic code compiled at runtime can conceal any number of attacks that will not appear in the baseline. The
use of dynamically compiled code could also allow the injection of attacks on post-deployed applications.
 Taxonomy Mappings
Mapped T axonomy Name Node ID Fit Mapped Node Name
Landwehr Trojan Horse
 Related Attack Patterns
CAPEC-ID Attack Pattern Name
CAPEC-698 Install Malicious Extension
 References
[REF-7] Michael Howard and David LeBlanc. "W riting Secure Code". Chapter 7, "V iruses, Trojans, and W orms In a Nutshell"
Page 208. 2nd Edition. Microsoft Press. 2002-12-04. < https://www .microsoftpressstore.com/store/writing-secure-code-
9780735617223 >.
 Content History
 Submissions
Submission Date Submitter Organization
2006-07-19
(CWE Draft 3, 2006-07-19)Landwehr
 Modifications