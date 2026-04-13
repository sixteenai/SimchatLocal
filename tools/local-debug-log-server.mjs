import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const logDir = path.join(repoRoot, 'debug');
const logFile = path.join(logDir, 'browser-chat-storage.jsonl');
const host = '127.0.0.1';
const port = 43127;

fs.mkdirSync(logDir, { recursive: true });

function writeJsonLine(payload) {
  const line = JSON.stringify(payload);
  fs.appendFileSync(logFile, `${line}\n`, 'utf8');
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(payload));
}

const server = http.createServer((req, res) => {
  if (!req.url) {
    sendJson(res, 400, { ok: false, error: 'Missing URL' });
    return;
  }

  if (req.method === 'OPTIONS') {
    sendJson(res, 204, { ok: true });
    return;
  }

  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { ok: true, logFile });
    return;
  }

  if (req.method !== 'POST' || req.url !== '/simchat-debug') {
    sendJson(res, 404, { ok: false, error: 'Not found' });
    return;
  }

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    try {
      const parsed = raw ? JSON.parse(raw) : {};
      writeJsonLine({
        receivedAt: new Date().toISOString(),
        remoteAddress: req.socket.remoteAddress || '',
        userAgent: req.headers['user-agent'] || '',
        payload: parsed,
      });
      sendJson(res, 200, { ok: true });
    } catch (error) {
      writeJsonLine({
        receivedAt: new Date().toISOString(),
        remoteAddress: req.socket.remoteAddress || '',
        parseError: error instanceof Error ? error.message : String(error),
        raw,
      });
      sendJson(res, 400, { ok: false, error: 'Invalid JSON payload' });
    }
  });
});

server.listen(port, host, () => {
  process.stdout.write(`SimChat debug log server listening on http://${host}:${port}\n`);
  process.stdout.write(`Writing logs to ${logFile}\n`);
});

