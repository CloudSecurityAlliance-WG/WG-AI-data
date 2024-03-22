3/7/24, 3:12 PM CWE - CWE-939: Improper Authorization in Handler for Custom URL Scheme (4.14)
https://cwe.mitre.org/data/deﬁnitions/939.html 1/3
Common W eakness Enumeration
A community-developed list of SW & HW weaknesses that can become
vulnerabilities
Home Search
CWE-939: Improper Authorization in Handler for Custom URL Scheme
Weakness ID: 939
Vulnerability Mapping: 
View customized information:
 Description
The product uses a handler for a custom URL scheme, but it does not properly restrict which actors can invoke the handler using the
scheme.
 Extended Description
Mobile platforms and other architectures allow the use of custom URL schemes to facilitate communication between applications. In
the case of iOS, this is the only method to do inter-application communication. The implementation is at the developer's discretion
which may open security flaws in the application. An example could be potentially dangerous functionality such as modifying files
through a custom URL scheme.
 Relationships
 Relevant to the view "Research Concepts" (CWE-1000)
Nature Type ID Name
ChildOf 862 Missing Authorization
 Relevant to the view "Software Development" (CWE-699)
Nature Type ID Name
MemberOf 1212 Authorization Errors
 Relevant to the view "Architectural Concepts" (CWE-1008)
 Modes Of Introduction
Phase Note
Implementation REALIZA TION: This weakness is caused during implementation of an architectural security tactic.
 Applicable Platforms
Technologies
Class: Mobile (Undetermined Prevalence)
 Demonstrative Examples
Example 1
This iOS application uses a custom URL scheme. The replaceFileT ext action in the URL scheme allows an external application to
interface with the file incomingMessage.txt and replace the contents with the text field of the query string.
External Application
Application URL HandlerAbout ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼
ALLOWED
Abstraction: Base
Conceptual OperationalMapping
FriendlyComplete Custom
(good code) Example Language: Objective-C 
NSString \*stringURL = @"appscheme://replaceFileText?file=incomingMessage.txt&text=hello";
NSURL \*url = [NSURL URLWithString:stringURL];
[[UIApplication sharedApplication] openURL:url];
(bad code) 
- (BOOL)application:(UIApplication \*)application handleOpenURL:(NSURL \*)url {
if (!url) {
return NO;
}
NSString \*action = [url host];
if([action isEqualToString: @"replaceFileText"]) {
NSDictionary \*dict = [self parseQueryStringExampleFunction:[url query]];
//this function will write contents to a specified file
FileObject \*objectFile = [self writeToFile:[dict objectForKey: @"file"] withText:[dict objectForKey: @"text"]];
}3/7/24, 3:12 PM CWE - CWE-939: Improper Authorization in Handler for Custom URL Scheme (4.14)
https://cwe.mitre.org/data/deﬁnitions/939.html 2/3The handler has no restriction on who can use its functionality . The handler can be invoked using any method that invokes the URL
handler such as the following malicious iframe embedded on a web page opened by Safari.
The attacker can host a malicious website containing the iframe and trick users into going to the site via a crafted phishing email.
Since Safari automatically executes iframes, the user is not prompted when the handler executes the iframe code which automatically
invokes the URL handler replacing the bookmarks file with a list of malicious websites. Since replaceFileT ext is a potentially
dangerous action, an action that modifies data, there should be a sanity check before the writeT oFile:withT ext: function.
Example 2
These Android and iOS applications intercept URL loading within a W ebView and perform special actions if a particular URL scheme
is used, thus allowing the Javascript within the W ebView to communicate with the application:
A call into native code can then be initiated by passing parameters within the URL:
Because the application does not check the source, a malicious website loaded within this W ebView has the same access to the API
as a trusted site.
 Observed Examples
Reference Description
CVE-2013-5725 URL scheme has action replace which requires no user prompt and allows remote attackers to perform
undesired actions.
CVE-2013-5726 URL scheme has action follow and favorite which allows remote attackers to force user to perform
undesired actions.
 Potential Mitigations
Phase: Architecture and Design}
return YES;
}
(attack code) Example Language: HTML 

(bad code) Example Language: Java 
// Android
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url){
if (url.substring(0,14).equalsIgnoreCase("examplescheme:")){
if(url.substring(14,25).equalsIgnoreCase("getUserInfo")){
writeDataToView(view, UserData);
return false;
}
else{
return true;
}
}
}
(bad code) Example Language: Objective-C 
// iOS
-(BOOL) webView:(UIWebView \*)exWebView shouldStartLoadWithRequest:(NSURLRequest \*)exRequest navigationType:
(UIWebViewNavigationType)exNavigationType
{
NSURL \*URL = [exRequest URL];
if ([[URL scheme] isEqualToString:@"exampleScheme"])
{
NSString \*functionString = [URL resourceSpecifier];
if ([functionString hasPrefix:@"specialFunction"])
{
// Make data available back in webview.
UIWebView \*webView = [self writeDataToView:[URL query]];
}
return NO;
}
return YES;
}
(attack code) Example Language: JavaScript 
window.location = examplescheme://method?parameter=value3/7/24, 3:12 PM CWE - CWE-939: Improper Authorization in Handler for Custom URL Scheme (4.14)
https://cwe.mitre.org/data/deﬁnitions/939.html 3/3Utilize a user prompt pop-up to authorize potentially harmful actions such as those modifying data or dealing with sensitive
information.
When designing functionality of actions in the URL scheme, consider whether the action should be accessible to all mobile
applications, or if an allowlist of applications to interface with is appropriate.
 Memberships
Nature Type ID Name
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
[REF-938] Guillaume Ross. "Scheming for Privacy and Security". 2013-11-11. < https://brooksreview .net/2013/11/guest-
post\_scheming-for-privacy-and-security/ >. URL validated: 2023-04-07 .
 Content History
 Submissions
Submission Date Submitter Organization
2014-01-14
(CWE 2.6, 2014-02-19)CWE Content Team MITRE
 Modifications
