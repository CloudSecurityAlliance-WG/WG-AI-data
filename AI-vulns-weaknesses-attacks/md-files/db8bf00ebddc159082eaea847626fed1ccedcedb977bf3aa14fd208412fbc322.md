3/7/24, 3:05 PM CWE - CWE-618: Exposed Unsafe ActiveX Method (4.14)
https://cwe.mitre.org/data/deﬁnitions/618.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-618: Exposed Unsafe ActiveX Method
Weakness ID: 618
Vulnerability Mapping: 
View customized information:
 Description
An ActiveX control is intended for use in a web browser , but it exposes dangerous methods that perform actions that are outside of
the browser's security model (e.g. the zone or domain).
 Extended Description
ActiveX controls can exercise far greater control over the operating system than typical Java or javascript. Exposed methods can be
subject to various vulnerabilities, depending on the implemented behaviors of those methods, and whether input validation is
performed on the provided arguments. If there is no integrity checking or origin validation, this method could be invoked by attackers.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 749 Exposed Dangerous Method or Function
PeerOf 623 Unsafe ActiveX Control Marked Safe For Scripting
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 275 Permission Issues
 Modes Of Introduction
Phase Note
Architecture and Design
Implementation
 Common Consequences
Scope Impact Likelihood
OtherTechnical Impact: Other
 Observed Examples
Reference Description
CVE-2007-1120 download a file to arbitrary folders.
CVE-2006-6838 control downloads and executes a url in a parameter
CVE-2007-0321 resultant buf fer overflow
 Potential Mitigations
Phase: Implementation
If you must expose a method, make sure to perform input validation on all arguments, and protect against all possible
vulnerabilities.
Phase: Architecture and Design
Use code signing, although this does not protect against any weaknesses that are already in the control.
Phases: Architecture and Design; System Configuration
Where possible, avoid marking the control as safe for scripting.
 Weakness Ordinalities
Ordinality Description
Primary(where the weakness exists independent of other weaknesses)About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Variant
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:05 PM CWE - CWE-618: Exposed Unsafe ActiveX Method (4.14)
https://cwe.mitre.org/data/deﬁnitions/618.html 2/2
 Detection Methods
Automated Static Analysis
Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this
weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically , this is done by building a
model of data flow and control flow , then searching for potentially-vulnerable patterns that connect "sources" (origins of input)
with "sinks" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)
Effectiveness: High
 Memberships
Nature Type ID Name
MemberOf 977 SFP Secondary Cluster: Design
MemberOf 1416 Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the V ariant level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 References
[REF-503] Microsoft. "Developing Secure ActiveX Controls". 2005-04-13. < https://learn.microsoft.com/en-us/previous-
versions//ms533046(v=vs.85)?redirectedfrom=MSDN >. URL validated: 2023-04-07 .
[REF-62] Mark Dowd, John McDonald and Justin Schuh. "The Art of Software Security Assessment". Chapter 12, "ActiveX
Security", Page 749. 1st Edition. Addison W esley . 2006.
 Content History
 Submissions
Submission Date Submitter Organization
2007-05-07
(CWE Draft 6, 2007-05-07)CWE Content Team MITRE
 Modifications
