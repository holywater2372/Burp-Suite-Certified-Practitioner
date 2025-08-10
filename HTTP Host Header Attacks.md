The HTTP Host header is a mandatory request header as of **HTTP/1.1**. It specifies the domain name that the client wants to access. For example, when a user visits `https://portswigger.net/web-security`, their browser will compose a request containing a Host header as follows:
```
GET /web-security HTTP/1.1 
Host: portswigger.net
```
## Purpose
The purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with. If requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application.

When multiple applications are accessible via the same IP address, this is most commonly a result of one of the following scenarios.
### Virtual hosting
One possible scenario is when a single web server hosts multiple websites or applications. This could be multiple websites with a single owner, but it is also possible for websites with different owners to be hosted on a single, shared platform. This is less common than it used to be, but still occurs with some cloud-based SaaS solutions.

In either case, although each of these distinct websites will have a different domain name, they all share a common IP address with the server. Websites hosted in this way on a single server are known as "virtual hosts".
### Routing traffic via an intermediary
Another common scenario is when websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system. This could be a simple load balancer or a reverse proxy server of some kind. This setup is especially prevalent in cases where clients access the website via a content delivery network (CDN).

In this case, even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component. This presents some of the same challenges as virtual hosting because the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request.
### How does the HTTP Host header solve this problem?
In both of these scenarios, the Host header is relied on to specify the intended recipient. In the case of HTTP messages, when a browser sends the request, the target URL will resolve to the IP address of a particular server. When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly.

> We can test for vulnerabilities using the HTTP Headers in the following ways:
1. Supply an arbitrary Host Header
2. Check for flawed validation
```
GET /example HTTP/1.1 
Host: vulnerable-website.com:bad-stuff-here
```
3. Send ambiguous requests.
4. Inject duplicate Host headers.
```
GET /example HTTP/1.1 
Host: vulnerable-website.com 
Host: bad-stuff-here
```
5. Supply absolute URL
```
GET https://vulnerable-website.com/ HTTP/1.1 
Host: bad-stuff-here
```
6. Add line wrapping: **Indentation**
```
GET /example HTTP/1.1 
	Host: bad-stuff-here 
Host: vulnerable-website.com
```
6. Request Smuggling
7. Inject host override headers: Use **Para Miner** to find the hidden headers.
-  `X-Host`
- `X-Forwarded-Server`
- `X-HTTP-Host-Override`
- `Forwarded`
