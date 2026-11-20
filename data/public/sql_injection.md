# SQL Injection

## What it is

SQL injection happens when an application builds a database query by joining user input directly into the SQL string. An attacker can then type SQL syntax into a form field or URL parameter and change what the query does: read other users' data, bypass a login, modify records, or in some databases run operating-system commands.

A classic example is a login query built like `"SELECT * FROM users WHERE name = '" + username + "'"`. Entering `' OR '1'='1` as the username makes the condition always true.

## How to prevent it

Use parameterized queries (prepared statements) for every query that includes user input. The database driver sends the query structure and the data separately, so input can never be interpreted as SQL. In Python this looks like `cursor.execute("SELECT * FROM users WHERE name = %s", (username,))`.

ORMs such as SQLAlchemy or Django ORM parameterize queries by default, but raw-SQL escape hatches inside them are still vulnerable if they concatenate strings.

Apply least privilege to the database account the application uses: it should not be able to drop tables or read tables it does not need.

Validate input against an allow-list where the expected format is known (for example, numeric IDs or a fixed set of sort columns). Column and table names cannot be parameterized, so they must be checked against an allow-list.

## How to test for it

Look for places where input reaches a query: search boxes, filters, sort parameters, login forms, and API JSON bodies. Signs of injection include database error messages, different responses to `'` versus `''`, or timing differences with payloads such as `SLEEP(5)`. Tools like Burp Suite and sqlmap help confirm findings, but only test systems you are authorized to test.
