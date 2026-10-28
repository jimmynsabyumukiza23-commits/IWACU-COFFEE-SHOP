import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:http";
import { mkdirSync, readFileSync } from "node:fs";
import { basename, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const projectDirectory = fileURLToPath(new URL(".", import.meta.url));
const dataDirectory = process.env.IWACU_DATA_DIR || join(projectDirectory, "data");
const databasePath = join(dataDirectory, "iwacu.sqlite");
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1");
const sessionDurationMs = 7 * 24 * 60 * 60 * 1000;
const allowedItems = new Set([
    "Espresso", "Cappuccino", "Café Latte", "Iced Coffee", "Sandwich",
    "Eggs & Bread", "Chips", "Croissant", "Tea", "Lemon Juice",
    "Mango Juice", "Bottled Water"
]);
const allowedServices = new Set(["Dine-in", "Takeaway"]);
const staticPages = new Set([
    "UR.JI.html", "menu.html", "login.html", "order.html", "owner.html",
    "jimmy.jpg.jpg"
]);
const rateLimits = new Map();

mkdirSync(dataDirectory, { recursive: true });

const database = new DatabaseSync(databasePath);
database.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        phone TEXT NOT NULL,
        password_salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers(id),
        item TEXT NOT NULL,
        quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100),
        service TEXT NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    );
`);

const getCustomerByEmail = database.prepare(
    "SELECT id, full_name, email, phone, password_salt, password_hash FROM customers WHERE email = ?"
);
const insertCustomer = database.prepare(
    "INSERT INTO customers (full_name, email, phone, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)"
);
const insertSession = database.prepare(
    "INSERT INTO sessions (token_hash, customer_id, expires_at) VALUES (?, ?, ?)"
);
const getSessionCustomer = database.prepare(`
    SELECT customers.id, customers.full_name, customers.email, customers.phone
    FROM sessions
    JOIN customers ON customers.id = sessions.customer_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
`);
const deleteSession = database.prepare("DELETE FROM sessions WHERE token_hash = ?");
const deleteExpiredSessions = database.prepare("DELETE FROM sessions WHERE expires_at <= ?");
const insertOrder = database.prepare(`
    INSERT INTO orders (customer_id, item, quantity, service, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
`);

function sendJson(response, statusCode, data, headers = {}) {
    response.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        ...headers
    });
    response.end(JSON.stringify(data));
}

function getCookie(request, name) {
    const cookieHeader = request.headers.cookie || "";
    for (const cookie of cookieHeader.split(";")) {
        const separator = cookie.indexOf("=");
        if (separator < 0) continue;
        if (cookie.slice(0, separator).trim() === name) {
            return cookie.slice(separator + 1).trim();
        }
    }
    return "";
}

function hashToken(token) {
    return createHash("sha256").update(token).digest("hex");
}

function getAuthenticatedCustomer(request) {
    const token = getCookie(request, "iwacu_session");
    if (!/^[a-f0-9]{64}$/.test(token)) return null;
    return getSessionCustomer.get(hashToken(token), Date.now()) || null;
}

function setSessionCookie(response, token) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader(
        "Set-Cookie",
        `iwacu_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionDurationMs / 1000)}${secure}`
    );
}

function clearSessionCookie(response) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    response.setHeader(
        "Set-Cookie",
        `iwacu_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`
    );
}

function allowRequest(request, response, limit = 8) {
    const address = request.socket.remoteAddress || "unknown";
    const now = Date.now();
    const existing = rateLimits.get(address);
    if (!existing || now - existing.startedAt >= 15 * 60 * 1000) {
        rateLimits.set(address, { startedAt: now, count: 1 });
        return true;
    }
    existing.count += 1;
    if (existing.count <= limit) return true;
    sendJson(response, 429, { error: "Too many attempts. Please wait 15 minutes and try again." });
    return false;
}

function validatePhone(value) {
    if (typeof value !== "string") return false;
    const phone = value.trim();
    const digits = phone.replace(/\D/g, "").length;
    return /^\+?[0-9\s().-]+$/.test(phone) && digits >= 7 && digits <= 15;
}

function validateEmail(value) {
    return typeof value === "string" &&
        value.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

async function readJson(request) {
    const contentType = request.headers["content-type"] || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
        const error = new Error("Send request data as JSON.");
        error.statusCode = 415;
        throw error;
    }

    let body = "";
    for await (const chunk of request) {
        body += chunk;
        if (Buffer.byteLength(body, "utf8") > 16 * 1024) {
            const error = new Error("Request is too large.");
            error.statusCode = 413;
            throw error;
        }
    }

    try {
        const parsed = JSON.parse(body);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Expected an object.");
        }
        return parsed;
    } catch {
        const error = new Error("Request body must be valid JSON.");
        error.statusCode = 400;
        throw error;
    }
}

function verifySameOrigin(request) {
    const origin = request.headers.origin;
    if (!origin) return true;
    try {
        return new URL(origin).host === request.headers.host;
    } catch {
        return false;
    }
}

async function createCustomerSession(customerId, response) {
    const token = randomBytes(32).toString("hex");
    const expiresAt = Date.now() + sessionDurationMs;
    insertSession.run(hashToken(token), customerId, expiresAt);
    setSessionCookie(response, token);
}

function customerResponse(customer) {
    return {
        id: Number(customer.id),
        name: customer.full_name,
        email: customer.email,
        phone: customer.phone
    };
}

async function handleApi(request, response, pathname) {
    if (request.method === "GET" && pathname === "/api/health") {
        return sendJson(response, 200, { status: "ok" });
    }

    if (request.method === "GET" && pathname === "/api/me") {
        const customer = getAuthenticatedCustomer(request);
        if (!customer) return sendJson(response, 200, { customer: null });
        return sendJson(response, 200, { customer: customerResponse(customer) });
    }

    if (request.method === "POST" && !verifySameOrigin(request)) {
        return sendJson(response, 403, { error: "Request origin was rejected." });
    }

    if (request.method === "POST" && pathname === "/api/register") {
        if (!allowRequest(request, response)) return;
        const body = await readJson(request);
        const name = typeof body.name === "string" ? body.name.trim() : "";
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const phone = typeof body.phone === "string" ? body.phone.trim() : "";
        const password = typeof body.password === "string" ? body.password : "";

        if (name.length < 2 || name.length > 100) {
            return sendJson(response, 400, { error: "Enter a name between 2 and 100 characters." });
        }
        if (!validateEmail(email)) return sendJson(response, 400, { error: "Enter a valid email address." });
        if (!validatePhone(phone)) return sendJson(response, 400, { error: "Enter a valid phone number." });
        if (password.length < 10 || password.length > 128) {
            return sendJson(response, 400, { error: "Password must be between 10 and 128 characters." });
        }
        if (getCustomerByEmail.get(email)) {
            return sendJson(response, 409, { error: "An account with that email already exists. Sign in instead." });
        }

        const salt = randomBytes(16);
        const passwordHash = await scrypt(password, salt, 64);
        const result = insertCustomer.run(name, email, phone, salt, passwordHash, Date.now());
        await createCustomerSession(Number(result.lastInsertRowid), response);
        deleteExpiredSessions.run(Date.now());
        return sendJson(response, 201, {
            message: "Account created. You are signed in.",
            customer: { name, email, phone }
        });
    }

    if (request.method === "POST" && pathname === "/api/login") {
        if (!allowRequest(request, response)) return;
        const body = await readJson(request);
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const phone = typeof body.phone === "string" ? body.phone.trim() : "";
        const password = typeof body.password === "string" ? body.password : "";
        const customer = getCustomerByEmail.get(email);

        if (!customer || customer.phone !== phone || password.length > 128) {
            return sendJson(response, 401, { error: "Email, phone number, or password is incorrect." });
        }

        const suppliedHash = await scrypt(password, customer.password_salt, 64);
        if (!timingSafeEqual(suppliedHash, customer.password_hash)) {
            return sendJson(response, 401, { error: "Email, phone number, or password is incorrect." });
        }

        await createCustomerSession(Number(customer.id), response);
        deleteExpiredSessions.run(Date.now());
        return sendJson(response, 200, {
            message: "Signed in successfully.",
            customer: customerResponse(customer)
        });
    }

    if (request.method === "POST" && pathname === "/api/logout") {
        const token = getCookie(request, "iwacu_session");
        if (token) deleteSession.run(hashToken(token));
        clearSessionCookie(response);
        return sendJson(response, 200, { message: "Signed out." });
    }

    if (request.method === "POST" && pathname === "/api/orders") {
        const customer = getAuthenticatedCustomer(request);
        if (!customer) return sendJson(response, 401, { error: "Sign in before placing an order." });

        const body = await readJson(request);
        const quantity = Number(body.quantity);
        const notes = typeof body.notes === "string" ? body.notes.trim() : "";
        if (!allowedItems.has(body.item)) return sendJson(response, 400, { error: "Choose an item from the menu." });
        if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
            return sendJson(response, 400, { error: "Quantity must be between 1 and 100." });
        }
        if (!allowedServices.has(body.service)) return sendJson(response, 400, { error: "Choose a valid service type." });
        if (notes.length > 500) return sendJson(response, 400, { error: "Instructions must be 500 characters or fewer." });

        const result = insertOrder.run(
            Number(customer.id), body.item, quantity, body.service, notes, Date.now()
        );
        return sendJson(response, 201, {
            message: "Your order was saved. The team will confirm it by phone.",
            orderId: Number(result.lastInsertRowid)
        });
    }

    return sendJson(response, 404, { error: "API endpoint not found." });
}

function sendStaticFile(request, response, pathname) {
    let requestedName;
    try {
        requestedName = decodeURIComponent(pathname === "/" ? "UR.JI.html" : pathname.slice(1));
    } catch {
        response.writeHead(400).end("Bad request");
        return;
    }

    if (basename(requestedName) !== requestedName || !staticPages.has(requestedName)) {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not found");
        return;
    }

    let content;
    try {
        content = readFileSync(join(projectDirectory, requestedName));
    } catch (error) {
        if (error.code !== "ENOENT") throw error;
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not found");
        return;
    }

    const contentTypes = {
        ".html": "text/html; charset=utf-8",
        ".jpg": "image/jpeg"
    };
    response.writeHead(200, {
        "Content-Type": contentTypes[extname(requestedName)] || "application/octet-stream",
        "Cache-Control": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin"
    });
    response.end(request.method === "HEAD" ? undefined : content);
}

function getPublicOrigin(request) {
    const forwardedProtocol = (request.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
    const protocol = forwardedProtocol === "https" ? "https:" : "http:";
    return new URL(`${protocol}//${request.headers.host}`).origin;
}

function sendRobotsFile(request, response) {
    const sitemapUrl = new URL("/sitemap.xml", getPublicOrigin(request));
    response.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff"
    });
    response.end(`User-agent: *\nAllow: /\nSitemap: ${sitemapUrl.href}\n`);
}

function sendSitemapFile(request, response) {
    const origin = getPublicOrigin(request);
    const urls = ["/", "/menu.html"];
    const entries = urls.map(path => `  <url><loc>${new URL(path, origin).href}</loc></url>`).join("\n");
    response.writeHead(200, {
        "Content-Type": "application/xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff"
    });
    response.end(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries}\n</urlset>`);
}

const server = createServer(async (request, response) => {
    try {
        const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
        if (requestUrl.pathname.startsWith("/api/")) {
            await handleApi(request, response, requestUrl.pathname);
            return;
        }
        if (request.method === "GET" && requestUrl.pathname === "/robots.txt") {
            sendRobotsFile(request, response);
            return;
        }
        if (request.method === "GET" && requestUrl.pathname === "/sitemap.xml") {
            sendSitemapFile(request, response);
            return;
        }
        if ((request.method === "GET" || request.method === "HEAD") &&
            requestUrl.pathname === "/index.html") {
            response.writeHead(301, { Location: "/" }).end();
            return;
        }
        if (request.method !== "GET" && request.method !== "HEAD") {
            response.writeHead(405, { Allow: "GET, HEAD" }).end("Method not allowed");
            return;
        }
        sendStaticFile(request, response, requestUrl.pathname);
    } catch (error) {
        if (response.headersSent) {
            response.destroy(error);
            return;
        }
        sendJson(response, error.statusCode || 500, {
            error: error.statusCode ? error.message : "The request could not be completed."
        });
        if (!error.statusCode) console.error(error);
    }
});

server.listen(port, host, () => {
    console.log(`Iwacu Coffee Shop is running at http://127.0.0.1:${port}`);
    console.log(`SQLite database: ${databasePath}`);
});

function closeDatabase() {
    server.close(() => {
        database.close();
        process.exit(0);
    });
}

process.on("SIGINT", closeDatabase);
process.on("SIGTERM", closeDatabase);
