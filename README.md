# TheGameIndex CMS

## Runtime
- Node.js + Express
- PostgreSQL for articles and sessions
- Secure HTTP-only session cookies; bcrypt password hash; Helmet security headers; login rate limiting.
- Public routes: `/`, `/story/:slug`
- Admin editor: `/admin`

## Required Render environment variables
Set these in Render Dashboard → Web Service → Environment:
- `DATABASE_URL`: PostgreSQL **internal** connection string for the Render database.
- `SESSION_SECRET`: a long random secret (32+ random bytes).
- `ADMIN_EMAIL`: your admin email.
- `ADMIN_PASSWORD_HASH`: bcrypt hash of your password (never store a plain password in GitHub).

Generate a bcrypt hash locally with Node:
```bash
node -e "require('bcryptjs').hash(process.argv[1], 12).then(console.log)" "YOUR-CHOSEN-PASSWORD"
```
Copy the printed hash into `ADMIN_PASSWORD_HASH` in Render. Do not put secrets in source files or commit them to GitHub.

## Deploy
Render web service: build command `npm install`; start command `npm start`; Node runtime. Set the environment variables above. Database must be ready before the app starts. The app creates its article and session tables on startup.

The original static site can remain available, but the CMS-enabled website should be the Node web service URL. The static site does not execute the Express routes.
