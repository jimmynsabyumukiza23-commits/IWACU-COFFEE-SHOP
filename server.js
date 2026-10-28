import { createHash, randomBytes, randomInt, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
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
const resetCodeDurationMs = 10 * 60 * 1000;
const maxResetCodeAttempts = 5;
const resetEmailMessage = "If an account exists for that email, a verification code has been sent.";
const allowedItems = new Set([
    "Espresso", "Cappuccino", "Café Latte", "Iced Coffee", "Sandwich",
    "Eggs & Bread", "Chips", "Croissant", "Tea", "Lemon Juice",
    "Mango Juice", "Bottled Water"
]);
const allowedServices = new Set(["Dine-in", "Takeaway"]);
const staticPages = new Set([
    "UR.JI.html", "menu.html", "login.html", "order.html", "owner.html",
    "jimmy.jpg.jpg", "table.jpg"
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

    CREATE TABLE IF NOT EXISTS password_reset_codes (
        customer_id INTEGER PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
        code_salt BLOB NOT NULL,
        code_hash BLOB NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS password_reset_codes_expiry ON password_reset_codes(expires_at);

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers(id),
        item TEXT NOT NULL,
        quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100),
        service TEXT NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS story_comments (
        id INTEGER PRIMARY KEY,
        display_name TEXT NOT NULL,
        message TEXT NOT NULL,
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
const deleteCustomerSessions = database.prepare("DELETE FROM sessions WHERE customer_id = ?");
const deleteExpiredSessions = database.prepare("DELETE FROM sessions WHERE expires_at <= ?");
const updateCustomerPassword = database.prepare(
    "UPDATE customers SET password_salt = ?, password_hash = ? WHERE id = ?"
);
const insertPasswordResetCode = database.prepare(`
    INSERT INTO password_reset_codes (customer_id, code_salt, code_hash, attempts, created_at, expires_at)
    VALUES (?, ?, ?, 0, ?, ?)
    ON CONFLICT(customer_id) DO UPDATE SET
        code_salt = excluded.code_salt,
        code_hash = excluded.code_hash,
        attempts = 0,
        created_at = excluded.created_at,
        expires_at = excluded.expires_at
`);
const getPasswordResetCode = database.prepare(`
    SELECT customers.id AS customer_id, password_reset_codes.code_salt,
        password_reset_codes.code_hash, password_reset_codes.attempts,
        password_reset_codes.expires_at
    FROM password_reset_codes
    JOIN customers ON customers.id = password_reset_codes.customer_id
    WHERE customers.email = ?
`);
const incrementPasswordResetAttempts = database.prepare(`
    UPDATE password_reset_codes
    SET attempts = attempts + 1
    WHERE customer_id = ? AND expires_at > ? AND attempts < ?
`);
const deletePasswordResetCode = database.prepare(
    "DELETE FROM password_reset_codes WHERE customer_id = ?"
);
const insertOrder = database.prepare(`
    INSERT INTO orders (customer_id, item, quantity, service, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
`);
const getStoryComments = database.prepare(`
    SELECT id, display_name, message, created_at
    FROM story_comments
    ORDER BY created_at DESC, id DESC
    LIMIT 50
`);
const insertStoryComment = database.prepare(`
    INSERT INTO story_comments (display_name, message, created_at)
    VALUES (?, ?, ?)
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

function allowRequest(request, response, limit = 8, scope = "auth") {
    const address = request.socket.remoteAddress || "unknown";
    const now = Date.now();
    const key = `${scope}:${address}`;
    const existing = rateLimits.get(key);
    if (!existing || now - existing.startedAt >= 15 * 60 * 1000) {
        rateLimits.set(key, { startedAt: now, count: 1 });
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

async function sendPasswordResetEmail(email, code) {
    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.EMAIL_FROM;
    if (!apiKey || !from) {
        const error = new Error("Password reset email is not configured.");
        error.statusCode = 503;
        throw error;
    }

    const result = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from,
            to: [email],
            subject: "Your Iwacu Coffee Shop password reset code",
            text: `Your password reset code is ${code}.\n\nIt expires in 10 minutes and can only be used once. If you did not request this code, you can ignore this email.`
        }),
        signal: AbortSignal.timeout(10000)
    });

    if (!result.ok) {
        const error = new Error("Password reset email delivery failed.");
        error.statusCode = 503;
        error.deliveryFailure = true;
        throw error;
    }
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

    if (request.method === "GET" && pathname === "/api/story-comments") {
        const comments = getStoryComments.all().map(comment => ({
            id: Number(comment.id),
            name: comment.display_name,
            message: comment.message,
            createdAt: Number(comment.created_at)
        }));
        return sendJson(response, 200, { comments });
    }

    if (request.method === "GET" && pathname === "/api/me") {
        const customer = getAuthenticatedCustomer(request);
        if (!customer) return sendJson(response, 200, { customer: null });
        return sendJson(response, 200, { customer: customerResponse(customer) });
    }

    if (request.method === "POST" && !verifySameOrigin(request)) {
        return sendJson(response, 403, { error: "Request origin was rejected." });
    }

    if (request.method === "POST" && pathname === "/api/story-comments") {
        if (!allowRequest(request, response, 5, "story-comments")) return;
        const body = await readJson(request);
        const name = typeof body.name === "string" ? body.name.trim() : "";
        const message = typeof body.message === "string" ? body.message.trim() : "";

        if (name.length < 2 || name.length > 60) {
            return sendJson(response, 400, { error: "Enter a name between 2 and 60 characters." });
        }
        if (!message || message.length > 500) {
            return sendJson(response, 400, { error: "Enter a comment of 1 to 500 characters." });
        }

        const createdAt = Date.now();
        const result = insertStoryComment.run(name, message, createdAt);
        return sendJson(response, 201, {
            comment: {
                id: Number(result.lastInsertRowid),
                name,
                message,
                createdAt
            }
        });
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
        const password = typeof body.password === "string" ? body.password : "";
        const customer = getCustomerByEmail.get(email);

        if (!customer || password.length > 128) {
            return sendJson(response, 401, { error: "Email or password is incorrect." });
        }

        const suppliedHash = await scrypt(password, customer.password_salt, 64);
        if (!timingSafeEqual(suppliedHash, customer.password_hash)) {
            return sendJson(response, 401, { error: "Email or password is incorrect." });
        }

        await createCustomerSession(Number(customer.id), response);
        deleteExpiredSessions.run(Date.now());
        return sendJson(response, 200, {
            message: "Signed in successfully.",
            customer: customerResponse(customer)
        });
    }

    if (request.method === "POST" && pathname === "/api/password-reset/request") {
        if (!allowRequest(request, response, 3, "password-reset-request")) return;
        const body = await readJson(request);
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        if (!validateEmail(email)) return sendJson(response, 400, { error: "Enter a valid email address." });

        if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) {
            return sendJson(response, 503, {
                error: "Password reset email is not configured yet. Please contact the shop for help."
            });
        }

        const customer = getCustomerByEmail.get(email);
        if (!customer) return sendJson(response, 200, { message: resetEmailMessage });

        const code = String(randomInt(0, 100000000)).padStart(8, "0");
        const salt = randomBytes(16);
        const codeHash = await scrypt(code, salt, 64);
        const now = Date.now();
        insertPasswordResetCode.run(
            Number(customer.id), salt, codeHash, now, now + resetCodeDurationMs
        );

        try {
            await sendPasswordResetEmail(email, code);
        } catch (error) {
            deletePasswordResetCode.run(Number(customer.id));
            if (error.deliveryFailure || error.statusCode !== 503) {
                console.error("Password reset email delivery failed:", error.message);
            }
            return sendJson(response, 503, {
                error: "Password reset email could not be sent right now. Please try again later."
            });
        }

        return sendJson(response, 200, { message: resetEmailMessage });
    }

    if (request.method === "POST" && pathname === "/api/password-reset/complete") {
        if (!allowRequest(request, response, 8, "password-reset-complete")) return;
        const body = await readJson(request);
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const code = typeof body.code === "string" ? body.code.trim() : "";
        const password = typeof body.password === "string" ? body.password : "";

        if (!validateEmail(email)) return sendJson(response, 400, { error: "Enter a valid email address." });
        if (!/^\d{8}$/.test(code)) {
            return sendJson(response, 400, { error: "Enter the 8-digit verification code from your email." });
        }
        if (password.length < 10 || password.length > 128) {
            return sendJson(response, 400, { error: "Password must be between 10 and 128 characters." });
        }

        const reset = getPasswordResetCode.get(email);
        if (!reset || reset.expires_at <= Date.now() || reset.attempts >= maxResetCodeAttempts) {
            if (reset) deletePasswordResetCode.run(Number(reset.customer_id));
            return sendJson(response, 400, { error: "The code is invalid or expired. Request a new code." });
        }

        const incremented = incrementPasswordResetAttempts.run(
            Number(reset.customer_id), Date.now(), maxResetCodeAttempts
        );
        if (incremented.changes !== 1) {
            return sendJson(response, 400, { error: "The code is invalid or expired. Request a new code." });
        }

        const suppliedHash = await scrypt(code, reset.code_salt, 64);
        if (!timingSafeEqual(suppliedHash, reset.code_hash)) {
            if (reset.attempts + 1 >= maxResetCodeAttempts) {
                deletePasswordResetCode.run(Number(reset.customer_id));
            }
            return sendJson(response, 400, { error: "The code is invalid or expired. Request a new code." });
        }

        const passwordSalt = randomBytes(16);
        const passwordHash = await scrypt(password, passwordSalt, 64);
        database.exec("BEGIN IMMEDIATE");
        try {
            const currentReset = getPasswordResetCode.get(email);
            if (!currentReset ||
                currentReset.expires_at <= Date.now() ||
                !timingSafeEqual(currentReset.code_hash, reset.code_hash)) {
                database.exec("ROLLBACK");
                return sendJson(response, 400, { error: "The code is invalid or expired. Request a new code." });
            }
            updateCustomerPassword.run(passwordSalt, passwordHash, Number(reset.customer_id));
            deleteCustomerSessions.run(Number(reset.customer_id));
            deletePasswordResetCode.run(Number(reset.customer_id));
            database.exec("COMMIT");
        } catch (error) {
            database.exec("ROLLBACK");
            throw error;
        }

        return sendJson(response, 200, { message: "Password updated. Sign in with your new password." });
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
