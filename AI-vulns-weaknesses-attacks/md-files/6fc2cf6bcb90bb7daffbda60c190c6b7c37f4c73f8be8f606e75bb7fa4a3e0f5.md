3/7/24, 3:10 PM CWE - CWE-795: Only Filtering Special Elements at a Speciﬁed Location (4.14)
https://cwe.mitre.org/data/deﬁnitions/795.html 1/2
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-795: Only Filtering Special Elements at a Specified Location
Weakness ID: 795
Vulnerability Mapping: 
View customized information:
 Description
The product receives data from an upstream component, but only accounts for special elements at a specified location, thereby
missing remaining special elements that may exist before sending it to a downstream component.
 Extended Description
A filter might only account for instances of special elements when they occur:
relative to a marker (e.g. "at the beginning/end of string; the second argument"), or
at an absolute position (e.g. "byte number 10").
This may leave special elements in the data that did not match the filter position, but still may be dangerous.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 791 Incomplete Filtering of Special Elements
ParentOf 796 Only Filtering Special Elements Relative to a Marker
ParentOf 797 Only Filtering Special Elements at an Absolute Position
 Relevant to the view "Architectural Concepts" (CWE-1008)
 Modes Of Introduction
Phase Note
Implementation REALIZA TION: This weakness is caused during implementation of an architectural security tactic.
 Common Consequences
Scope Impact Likelihood
IntegrityTechnical Impact: Unexpected State
 Demonstrative Examples
Example 1
The following code takes untrusted input and uses a regular expression to filter a "../" element located at the beginning of the input
string. It then appends this result to the /home/user/ directory and attempts to read the file in the final resulting path.
Since the regular expression is only looking for an instance of "../" at the beginning of the string, it only removes the first "../" element.
So an input value such as:
will have the first "../" stripped, resulting in:About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
(bad code) Example Language: Perl 
my $Username = GetUntrustedInput();
$Username =~ s/^\.\.\///;
my $filename = "/home/user/" . $Username;
ReadAndSendFile($filename);
(attack code) 
../../../etc/passwd
(result) 
../../etc/passwd3/7/24, 3:10 PM CWE - CWE-795: Only Filtering Special Elements at a Speciﬁed Location (4.14)
https://cwe.mitre.org/data/deﬁnitions/795.html 2/2This value is then concatenated with the /home/user/ directory:
which causes the /etc/passwd file to be retrieved once the operating system has resolved the ../ sequences in the pathname. This
leads to relative path traversal ( CWE-22 ).
Example 2
The following code takes untrusted input and uses a substring function to filter a 3-character "../" element located at the 0-index
position of the input string. It then appends this result to the /home/user/ directory and attempts to read the file in the final resulting
path.
Since the if function is only looking for a substring of "../" between the 0 and 2 position, it only removes that specific "../" element. So
an input value such as:
will have the first "../" filtered, resulting in:
This value is then concatenated with the /home/user/ directory:
which causes the /etc/passwd file to be retrieved once the operating system has resolved the ../ sequences in the pathname. This
leads to relative path traversal ( CWE-22 ).
 Memberships
Nature Type ID Name
MemberOf 1407 Comprehensive Categorization: Improper Neutralization
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID could be used to map to real-world vulnerabilities)
Reason: Acceptable-Use
Rationale:
This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of
vulnerabilities.
Comments:
Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a
lower-level Base/V ariant simply to comply with this preferred level of abstraction.
 Content History
 Submissions
Submission Date Submitter Organization
2009-12-04
(CWE 1.7, 2009-12-28)CWE Content Team MITRE
 Modifications
(result) 
/home/user/../../etc/passwd
(bad code) Example Language: Perl 
my $Username = GetUntrustedInput();
if (substr($Username, 0, 3) eq '../') {
$Username = substr($Username, 3);
}
my $filename = "/home/user/" . $Username;
ReadAndSendFile($filename);
(attack code) 
../../../etc/passwd
(result) 
../../etc/passwd
(result) 
/home/user/../../etc/passwd