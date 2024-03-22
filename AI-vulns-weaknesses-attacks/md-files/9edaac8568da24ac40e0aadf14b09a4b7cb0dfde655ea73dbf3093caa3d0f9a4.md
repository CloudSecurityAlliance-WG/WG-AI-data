3/7/24, 3:10 PM CWE - CWE-821: Incorrect Synchronization (4.14)
https://cwe.mitre.org/data/deﬁnitions/821.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-821: Incorrect Synchronization
Weakness ID: 821
Vulnerability Mapping: 
View customized information:
 Description
The product utilizes a shared resource in a concurrent manner , but it does not correctly synchronize access to the resource.
 Extended Description
If access to a shared resource is not correctly synchronized, then the resource may not be in a state that is expected by the product.
This might lead to unexpected or insecure behaviors, especially if an attacker can influence the shared resource.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 662 Improper Synchronization
ParentOf 572 Call to Thread run() instead of start()
ParentOf 574 EJB Bad Practices: Use of Synchronization Primitives
ParentOf 1088 Synchronous Access of Remote Resource without Timeout
ParentOf 1264 Hardware Logic with Insecure De-Synchronization between Control and Data Channels
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 557 Concurrency Issues
 Relevant to the view "CISQ Quality Measures (2020)" (CWE-1305)
 Relevant to the view "CISQ Data Protection Measures" (CWE-1340)
 Common Consequences
Scope Impact Likelihood
Integrity
Confidentiality
OtherTechnical Impact: Modify Application Data; Read Application Data; Alter Execution Logic
 Memberships
Nature Type ID Name
MemberOf 1401 Comprehensive Categorization: Concurrency
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
Maintenance
Deeper research is necessary for synchronization and related mechanisms, including locks, mutexes, semaphores, and other
mechanisms. Multiple entries are dependent on this research, which includes relationships to concurrency , race conditions, reentrant
functions, etc. CWE-662 and its children - including CWE-667 , CWE-820 , CWE-821 , and others - may need to be modified
significantly , along with their relationships.About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:10 PM CWE - CWE-821: Incorrect Synchronization (4.14)
https://cwe.mitre.org/data/deﬁnitions/821.html 2/2
 Content History
 Submissions
Submission Date Submitter Organization
2010-08-06
(CWE 1.10, 2010-09-27)CWE Content Team MITRE
 Modifications