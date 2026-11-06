require('dotenv').config();
const http = require("http");
const crypto = require("crypto");
const url = require("url");
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8081;
const JWT_SECRET = process.env.JWT_SECRET;
const RELAY_SECRET = process.env.WS_RELAY_SECRET;

if (!JWT_SECRET || !RELAY_SECRET) {
    console.error('JWT_SECRET and WS_RELAY_SECRET must both be set in ws-server/.env, refusing to start.');
    process.exit(1);
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, "/");
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64');
}

function verifyJwt(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;

    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${headerB64}.${payloadB64}`).digest();
    const actual = base64urlDecode(signatureB64);
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
        return null;
    }
    let payload;
    try {
        payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8'));
    } catch {
        return null;
    }
    if (!payload || typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
    }
    return payload;
}

const clients = new Map();

function addClient(userId, ws) {
    if (!clients.has(userId)) clients.set(userId, new Set());
    clients.get(userId).add(ws);
}

function removeClient(userId, ws) {
    const set = clients.get(userId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0) clients.delete(userId);
}

const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === '/relay') {
        if (req.headers['x-internal-secret'] !== RELAY_SECRET) {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Unauthorized" }));
            return;
        }

        let body = "";
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
            let payload;
            try {
                payload = JSON.parse(body);
            } catch {
                res.writeHead(400, { "Content-Type": 'application/json' });
                res.end(JSON.stringify({ error: "Invalid JSON" }));
                return;
            }
            const { recipient_ids, message, from, sent_at,type } = payload;
            let delivered = 0;

            if (Array.isArray(recipient_ids)) {
                const frame = JSON.stringify({ type:type || "admin_message", message, from, sent_at });
                for (const id of recipient_ids) {
                    const set = clients.get(Number(id));
                    if (!set) continue;
                    for (const ws of set) {
                        if (ws.readyState === ws.OPEN) {
                            ws.send(frame);
                            delivered++;
                        }
                    }
                }
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ delivered }));
        });
        return;
    }
    res.writeHead(404);
    res.end();
});

const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
    const { pathname, query } = url.parse(req.url, true);
    if (pathname !== "/ws") {
        socket.destroy();
        return;
    }

    const payload = verifyJwt(query.token);
    if (!payload || !payload.sub) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
        ws.userId = Number(payload.sub);
        wss.emit('connection', ws, req);
    });
});

wss.on('connection', (ws) => {
    addClient(ws.userId, ws);
    console.log(`User ${ws.userId} connected (${clients.get(ws.userId).size} active connection(s)).`);
    ws.on('close', () => {
        removeClient(ws.userId, ws);
        console.log(`User ${ws.userId} disconnected.`);
    });
    ws.on('error', () => {
        removeClient(ws.userId, ws);
    });
});

server.listen(PORT, () => {
    console.log(`WS relay server listening on port ${PORT} (HTTP POST /relay, WebSocket /ws)`);
});
