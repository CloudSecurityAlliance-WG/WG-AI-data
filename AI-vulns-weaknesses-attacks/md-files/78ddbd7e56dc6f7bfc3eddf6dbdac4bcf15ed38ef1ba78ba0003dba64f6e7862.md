3/7/24, 3:11 PM CWE - CWE-837: Improper Enforcement of a Single, Unique Action (4.14)
https://cwe.mitre.org/data/deﬁnitions/837.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-837: Improper Enforcement of a Single, Unique Action
Weakness ID: 837
Vulnerability Mapping: 
View customized information:
 Description
The product requires that an actor should only be able to perform an action once, or to have only one unique action, but the product
does not enforce or improperly enforces this restriction.
 Extended Description
In various applications, a user is only expected to perform a certain action once, such as voting, requesting a refund, or making a
purchase. When this restriction is not enforced, sometimes this can have security implications. For example, in a voting application,
an attacker could attempt to "stuf f the ballot box" by voting multiple times. If these votes are counted separately , then the attacker
could directly af fect who wins the vote. This could have significant business impact depending on the purpose of the product.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 799 Improper Control of Interaction Frequency
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 438 Behavioral Problems
MemberOf 840 Business Logic Errors
 Applicable Platforms
Languages
Class: Not Language-Specific (Undetermined Prevalence)
 Common Consequences
Scope Impact Likelihood
OtherTechnical Impact: Varies by Context
An attacker might be able to gain advantage over other users by performing the action multiple times, or
affect the correctness of the product.
 Observed Examples
Reference Description
CVE-2008-0294 Ticket-booking web application allows a user to lock a seat more than once.
CVE-2005-4051 CMS allows people to rate downloads by voting more than once.
CVE-2002-216 Polling software allows people to vote more than once by setting a cookie.
CVE-2003-1433 Chain: lack of validation of a challenge key in a game allows a player to register multiple times and lock
other players out of the game.
CVE-2002-1018 Library feature allows attackers to check out the same e-book multiple times, preventing other users
from accessing copies of the e-book.
CVE-2009-2346 Protocol implementation allows remote attackers to cause a denial of service (call-number exhaustion)
by initiating many message exchanges.
 Memberships
Nature Type ID Name
MemberOf 1410 Comprehensive Categorization: Insuf ficient Control Flow Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-UseAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 3:11 PM CWE - CWE-837: Improper Enforcement of a Single, Unique Action (4.14)
https://cwe.mitre.org/data/deﬁnitions/837.html 2/2Rationale:
This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 Content History
 Submissions
Submission Date Submitter Organization
2011-03-24
(CWE 1.12, 2011-03-30)CWE Content Team MITRE
 Modifications