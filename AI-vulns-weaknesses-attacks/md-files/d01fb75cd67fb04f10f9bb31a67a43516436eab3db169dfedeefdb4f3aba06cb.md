3/7/24, 2:50 PM CWE - CWE-1393: Use of Default Password (4.14)
https://cwe.mitre.org/data/deﬁnitions/1393.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-1393: Use of Default Password
Weakness ID: 1393
Vulnerability Mapping: 
View customized information:
 Description
The product uses default passwords for potentially critical functionality .
 Extended Description
It is common practice for products to be designed to use default passwords for authentication. The rationale is to simplify the
manufacturing process or the system administrator's task of installation and deployment into an enterprise. However , if admins do not
change the defaults, then it makes it easier for attackers to quickly bypass authentication across multiple organizations. There are
many lists of default passwords and default-password scanning tools that are easily available from the W orld Wide W eb.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 1392 Use of Default Credentials
 Modes Of Introduction
Phase Note
Architecture and Design
 Applicable Platforms
Languages
Class: Not Language-Specific (Undetermined Prevalence)
Operating Systems
Class: Not OS-Specific (Undetermined Prevalence)
Architectures
Class: Not Architecture-Specific (Undetermined Prevalence)
Technologies
Class: Not Technology-Specific (Undetermined Prevalence)
Class: ICS/OT (Undetermined Prevalence)
 Common Consequences
Scope Impact Likelihood
AuthenticationTechnical Impact: Gain Privileges or Assume Identity
 Demonstrative Examples
Example 1
In 2022, the OT :ICEF ALL study examined products by 10 dif ferent Operational Technology (OT) vendors. The researchers reported 56
vulnerabilities and said that the products were "insecure by design" [ REF-1283 ]. If exploited, these vulnerabilities often allowed
adversaries to change how the products operated, ranging from denial of service to changing the code that the products executed.
Since these products were often used in industries such as power , electrical, water , and others, there could even be safety
implications.
Multiple OT products used default credentials.
 Observed Examples
Reference Description
CVE-2022-30270 Remote Terminal Unit (R TU) uses default credentials for some SSH accounts
CVE-2022-2336 OPC Unified Architecture (OPC UA) industrial automation product has a default password
CVE-2021-38759 microcontroller board has default password
CVE-2021-44480 children's smart watch has default passwords allowing attackers to send SMS commands and listen to
the device's surroundings
CVE-2020-11624 surveillance camera has default password for the admin accountAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
3/7/24, 2:50 PM CWE - CWE-1393: Use of Default Password (4.14)
https://cwe.mitre.org/data/deﬁnitions/1393.html 2/2CVE-2018-15719 medical dental records product installs a MySQL database with a blank default password
CVE-2014-9736 healthcare system for archiving patient images has default passwords for key management and
storage databases
CVE-2000-1209 database product installs admin account with default null password, allowing privileges, as exploited by
various worms
 Potential Mitigations
Phase: Requirements
Prohibit use of default, hard-coded, or other values that do not vary for each installation of the product - especially for separate
organizations.
Effectiveness: High
Phase: Documentation
Ensure that product documentation clearly emphasizes the presence of default passwords and provides steps for the
administrator to change them.
Effectiveness: Limited
Phase: Architecture and Design
Force the administrator to change the credential upon installation.
Effectiveness: High
Phases: Installation; Operation
The product administrator could change the defaults upon installation or during operation.
Effectiveness: Moderate
 Memberships
Nature Type ID Name
MemberOf 1364 ICS Communications: Zone Boundary Failures
MemberOf 1366 ICS Communications: Frail Security in Protocols
MemberOf 1368 ICS Dependencies (& Architecture): External Digital Systems
MemberOf 1376 ICS Engineering (Construction/Deployment): Security Gaps in Commissioning
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
 References
[REF-1283] Forescout V edere Labs. "OT :ICEF ALL: The legacy of "insecure by design" and its implications for certifications and
risk management". 2022-06-20. < https://www .forescout.com/resources/ot-icefall-report/ >.
[REF-1303] Kelly Jackson Higgins. "Researchers Out Default Passwords Packaged With ICS/SCADA Wares". 2016-01-04.
. URL validated:
2022-10-11 .
 Content History
 Submissions
Submission Date Submitter Organization
2022-10-07
(CWE 4.9, 2022-10-13)CWE Content Team MITRE
 Modifications
