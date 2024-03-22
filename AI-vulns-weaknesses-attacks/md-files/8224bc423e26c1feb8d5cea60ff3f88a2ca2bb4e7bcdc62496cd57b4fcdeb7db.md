3/7/24, 3:10 PM CWE - CWE-786: Access of Memory Location Before Start of Buﬀer (4.14)
https://cwe.mitre.org/data/deﬁnitions/786.html 1/3
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-786: Access of Memory Location Before Start of Buffer
Weakness ID: 786
Vulnerability Mapping: 
View customized information:
 Description
The product reads or writes to a buf fer using an index or pointer that references a memory location prior to the beginning of the buf fer.
 Extended Description
This typically occurs when a pointer or its index is decremented to a position before the buf fer, when pointer arithmetic results in a
position before the beginning of the valid memory location, or when a negative index is used.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 119 Improper Restriction of Operations within the Bounds of a Memory Buf fer
ParentOf 124 Buffer Underwrite ('Buf fer Underflow')
ParentOf 127 Buffer Under-read
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 1218 Memory Buf fer Errors
 Relevant to the view "CISQ Quality Measures (2020)" (CWE-1305)
 Relevant to the view "CISQ Data Protection Measures" (CWE-1340)
 Common Consequences
Scope Impact Likelihood
ConfidentialityTechnical Impact: Read Memory
For an out-of-bounds read, the attacker may have access to sensitive information. If the sensitive
information contains system details, such as the current buf fers position in memory , this knowledge
can be used to craft further attacks, possibly with more severe consequences.
Integrity
AvailabilityTechnical Impact: Modify Memory; DoS: Crash, Exit, or Restart
Out of bounds memory access will very likely result in the corruption of relevant memory , and
perhaps instructions, possibly leading to a crash.
IntegrityTechnical Impact: Modify Memory; Execute Unauthorized Code or Commands
If the corrupted memory can be ef fectively controlled, it may be possible to execute arbitrary code. If
the corrupted memory is data rather than instructions, the system will continue to function with
improper changes, possibly in violation of an implicit or explicit policy .
 Demonstrative Examples
Example 1
In the following C/C++ example, a utility function is used to trim trailing whitespace from a character string. The function copies the
input string to a local character string and uses a while statement to remove the trailing whitespace by moving backward through the
string and overwriting whitespace with a NUL character .About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
DISCOURAGED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
(bad code) Example Language: C 
char\* trimTrailingWhitespace(char \*strMessage, int length) {
char \*retMessage;
char \*message = malloc(sizeof(char)\*(length+1));
// copy input string to a temporary string
char message[length+1];
int index;
for (index = 0; index < length; index++) {
message[index] = strMessage[index];
}3/7/24, 3:10 PM CWE - CWE-786: Access of Memory Location Before Start of Buﬀer (4.14)
https://cwe.mitre.org/data/deﬁnitions/786.html 2/3However , this function can cause a buf fer underwrite if the input character string contains all whitespace. On some systems the while
statement will move backwards past the beginning of a character string and will call the isspace() function on an address outside of
the bounds of the local buf fer.
Example 2
The following example asks a user for an of fset into an array to select an item.
The programmer allows the user to specify which element in the list to select, however an attacker can provide an out-of-bounds
offset, resulting in a buf fer over-read ( CWE-126 ).
Example 3
The following is an example of code that may result in a buf fer underwrite. This code is attempting to replace the substring "Replace
Me" in destBuf with the string stored in srcBuf. It does so by using the function strstr(), which returns a pointer to the found substring
in destBuf. Using pointer arithmetic, the starting index of the substring is found.
In the case where the substring is not found in destBuf, strstr() will return NULL, causing the pointer arithmetic to be undefined,
potentially setting the value of idx to a negative number . If idx is negative, this will result in a buf fer underwrite of destBuf.
 Observed Examples
Reference Description
CVE-2002-2227 Unchecked length of SSLv2 challenge value leads to buf fer underflow .
CVE-2007-4580 Buffer underflow from a small size value with a large buf fer (length parameter inconsistency , CWE-130 )
CVE-2007-1584 Buffer underflow from an all-whitespace string, which causes a counter to be decremented before the
buffer while looking for a non-whitespace character .
CVE-2007-0886 Buffer underflow resultant from encoded data that triggers an integer overflow .
CVE-2006-6171 Product sets an incorrect buf fer size limit, leading to "of f-by-two" buf fer underflow .
CVE-2006-4024 Negative value is used in a memcpy() operation, leading to buf fer underflow .
CVE-2004-2620 Buffer underflow due to mishandled special characters
 Detection Methods
Fuzzing
Fuzz testing (fuzzing) is a powerful technique for generating large numbers of diverse inputs - either randomly or algorithmically
- and dynamically invoking the code with those inputs. Even with random inputs, it is often capable of generating unexpected
results such as crashes, memory corruption, or resource consumption. Fuzzing ef fectively produces repeatable test cases that
clearly indicate bugs, which helps developers to diagnose the issues.
Effectiveness: High
 Memberships
Nature Type ID Name
MemberOf 884 CWE Cross-section
}
message[index] = '\0';
// trim trailing whitespace
int len = index-1;
while (isspace(message[len])) {
message[len] = '\0';
len--;
}
// return string without trailing whitespace
retMessage = message;
return retMessage;
}
(bad code) Example Language: C 
int main (int argc, char \*\*argv) {
char \*items[] = {"boat", "car", "truck", "train"};
int index = GetUntrustedOffset();
printf("You selected %s\n", items[index-1]);
}
(bad code) Example Language: C 
int main() {
...
char \*result = strstr(destBuf, "Replace Me");
int idx = result - destBuf;
strcpy(&destBuf[idx], srcBuf);
...
}3/7/24, 3:10 PM CWE - CWE-786: Access of Memory Location Before Start of Buﬀer (4.14)
https://cwe.mitre.org/data/deﬁnitions/786.html 3/3MemberOf 1160 SEI CER T C Coding Standard - Guidelines 06. Arrays (ARR)
MemberOf 1399 Comprehensive Categorization: Memory Safety
 Vulnerability Mapping Notes
Usage: DISCOURAGED (this CWE ID should not be used to map to real-world vulnerabilities)
Reasons: Potential Deprecation, Frequent Misuse
Rationale:
The CWE entry might be misused when lower-level CWE entries might be available. It also overlaps existing CWE entries and
might be deprecated in the future.
Comments:
If the "Access" operation is known to be a read or a write, then investigate children of entries such as CWE-787 : Out-of-bounds
Write and CWE-125 : Out-of-bounds Read.
 Taxonomy Mappings
Mapped T axonomy Name Node ID Fit Mapped Node Name
CER T C Secure Coding ARR30-C CWE More
SpecificDo not form or use out-of-bounds pointers or array
subscripts
 Content History
 Submissions
Submission Date Submitter Organization
2009-10-21
(CWE 1.6, 2009-10-29)CWE Content Team MITRE
 Modifications
