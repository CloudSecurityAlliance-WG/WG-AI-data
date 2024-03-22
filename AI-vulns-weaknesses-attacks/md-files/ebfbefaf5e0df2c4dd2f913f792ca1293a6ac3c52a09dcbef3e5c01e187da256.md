3/7/24, 2:44 PM CWE - CWE-1127: Compilation with Insuﬃcient Warnings or Errors (4.14)
https://cwe.mitre.org/data/deﬁnitions/1127.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-1127: Compilation with Insufficient W arnings or Errors
Weakness ID: 1127
Vulnerability Mapping: 
View customized information:
 Description
The code is compiled without suf ficient warnings enabled, which may prevent the detection of subtle bugs or quality issues.
 Extended Description
This issue makes it more dif ficult to maintain the product, which indirectly af fects security by making it more dif ficult or time-consuming
to find and/or fix vulnerabilities. It also might make it easier to introduce vulnerabilities.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 710 Improper Adherence to Coding Standards
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 1006 Bad Coding Practices
 Modes Of Introduction
Phase Note
Build and Compilation
 Common Consequences
Scope Impact Likelihood
OtherTechnical Impact: Reduce Maintainability
 Weakness Ordinalities
Ordinality Description
Indirect(where the weakness is a quality issue that might indirectly make it easier to introduce security-relevant weaknesses or make
them more difficult to detect)
 Memberships
Nature Type ID Name
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
 Content HistoryAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 2:44 PM CWE - CWE-1127: Compilation with Insuﬃcient Warnings or Errors (4.14)
https://cwe.mitre.org/data/deﬁnitions/1127.html 2/2
 Submissions
Submission Date Submitter Organization
2018-07-02
(CWE 3.2, 2019-01-03)CWE Content Team MITRE
Entry derived from Common Quality Enumeration (CQE) Draft 0.9.
 Modifications