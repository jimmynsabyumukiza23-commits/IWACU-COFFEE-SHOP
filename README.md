# Iwacu Coffee Shop

## Run locally

Install Node.js 22.5 or newer, open PowerShell in this folder, and run:

```powershell
node server.js
```

Open <http://127.0.0.1:3000>. Do not open the HTML files directly with `file://`; the account and order forms need the local server.

The homepage is `UR.JI.html` and is served at `/`. The server also publishes `robots.txt` and a sitemap at `/sitemap.xml`.

Customers can create an account with their name, email, phone number, and a password of at least 10 characters. Passwords are stored as salted scrypt hashes. After signing in, customers can submit orders that are saved in `data/iwacu.sqlite`.

The SQLite database is private application data and is not served as a website file. Keep the `data` folder private and make secure backups if you need to preserve customer records. Do not commit or share the database.

This server binds to the local computer only. It is not publicly available on the internet. To make the site available to customers, deploy it using the included `render.yaml` configuration or another hosting provider with HTTPS, backups, privacy protections, and production monitoring; never expose this local server directly to the internet. After deployment, submit `https://your-public-domain/sitemap.xml` to search-engine webmaster tools. Search engines decide when and whether to index a site, so appearing in search results is not immediate or guaranteed.
