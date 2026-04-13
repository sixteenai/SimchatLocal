export interface Env {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN?: string;
  DEFAULT_REGION?: string;
  GOOGLE_API_KEY?: string;
  ALLOWED_USER_ID?: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(input) {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  const hash = await crypto.subtle.digest("SHA-256", data);
  return toHex(hash);
}

async function hmac(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, data);
}

async function getSigningKey(secretAccessKey, dateStamp, region, service) {
  const kDate = await hmac(encoder.encode("AWS4" + secretAccessKey), encoder.encode(dateStamp));
  const kRegion = await hmac(kDate, encoder.encode(region));
  const kService = await hmac(kRegion, encoder.encode(service));
  return hmac(kService, encoder.encode("aws4_request"));
}

function buildCanonicalHeaders(headers) {
  const entries = Array.from(headers.entries())
    .map(([key, value]) => [key.toLowerCase(), value.trim()])
    .sort(([a], [b]) => a.localeCompare(b));

  const canonical = entries.map(([key, value]) => `${key}:${value}\n`).join("");
  const signed = entries.map(([key]) => key).join(";");
  return { canonical, signed };
}

function getAmzDate(now) {
  const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return {
    amzDate: iso.slice(0, 15) + "Z",
    dateStamp: iso.slice(0, 8)
  };
}

async function signRequest({
  method,
  url,
  headers,
  body,
  accessKeyId,
  secretAccessKey,
  sessionToken,
  region
}) {
  const { amzDate, dateStamp } = getAmzDate(new Date());
  const payloadHash = await sha256Hex(body);
  headers.set("x-amz-date", amzDate);
  headers.set("x-amz-content-sha256", payloadHash);
  if (sessionToken) {
    headers.set("x-amz-security-token", sessionToken);
  }

  const canonicalUrl = new URL(url);
  const canonicalUri = canonicalUrl.pathname
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  const canonicalQuery = canonicalUrl.search ? canonicalUrl.search.slice(1) : "";

  const { canonical, signed } = buildCanonicalHeaders(headers);
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQuery,
    canonical,
    signed,
    payloadHash
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/bedrock/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest)
  ].join("\n");

  const signingKey = await getSigningKey(secretAccessKey, dateStamp, region, "bedrock");
  const signature = toHex(await hmac(signingKey, encoder.encode(stringToSign)));

  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signed}, Signature=${signature}`;
  headers.set("authorization", authorization);
  return { canonicalRequest, stringToSign, signedHeaders: signed };
}

function withCorsHeaders(base = {}) {
  const headers = new Headers(base);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  return headers;
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: withCorsHeaders({ "Content-Type": "application/json" })
  });
}


function concatBytes(a, b) {
  if (!a || a.length === 0) return b;
  if (!b || b.length === 0) return a;
  const merged = new Uint8Array(a.length + b.length);
  merged.set(a, 0);
  merged.set(b, a.length);
  return merged;
}

function readUInt32BE(buffer, offset) {
  return (
    (buffer[offset] << 24)
    | (buffer[offset + 1] << 16)
    | (buffer[offset + 2] << 8)
    | buffer[offset + 3]
  ) >>> 0;
}

function readUInt16BE(buffer, offset) {
  return ((buffer[offset] << 8) | buffer[offset + 1]) >>> 0;
}

function parseEventStreamHeaders(buffer) {
  const headers = {};
  let offset = 0;
  while (offset < buffer.length) {
    const nameLen = buffer[offset];
    offset += 1;
    if (offset + nameLen > buffer.length) break;
    const name = decoder.decode(buffer.slice(offset, offset + nameLen));
    offset += nameLen;
    const type = buffer[offset];
    offset += 1;
    let value = null;
    switch (type) {
      case 0: // boolean true
        value = true;
        break;
      case 1: // boolean false
        value = false;
        break;
      case 2: // byte
        value = buffer[offset];
        offset += 1;
        break;
      case 3: // short
        value = readUInt16BE(buffer, offset);
        offset += 2;
        break;
      case 4: // integer
        value = readUInt32BE(buffer, offset);
        offset += 4;
        break;
      case 5: // long
        offset += 8;
        break;
      case 6: { // byte array
        const length = readUInt16BE(buffer, offset);
        offset += 2 + length;
        break;
      }
      case 7: { // string
        const length = readUInt16BE(buffer, offset);
        offset += 2;
        value = decoder.decode(buffer.slice(offset, offset + length));
        offset += length;
        break;
      }
      case 8: // timestamp
        offset += 8;
        break;
      case 9: // uuid
        offset += 16;
        break;
      default:
        return headers;
    }
    headers[name] = value;
  }
  return headers;
}

function decodeEventStreamMessages(buffer, onMessage) {
  let working = buffer;
  while (working.length >= 12) {
    const totalLength = readUInt32BE(working, 0);
    const headersLength = readUInt32BE(working, 4);
    if (totalLength < 16 || totalLength > working.length) break;
    const headersStart = 12;
    const headersEnd = headersStart + headersLength;
    if (headersEnd > totalLength - 4) break;
    const payloadStart = headersEnd;
    const payloadEnd = totalLength - 4;
    const headersBytes = working.slice(headersStart, headersEnd);
    const payloadBytes = working.slice(payloadStart, payloadEnd);
    const headers = parseEventStreamHeaders(headersBytes);
    onMessage({ headers, payload: payloadBytes });
    working = working.slice(totalLength);
  }
  return working;
}

async function streamBedrockResponse(response) {
  if (!response.body || typeof response.body.getReader !== "function") {
    return jsonResponse({ error: "Streaming is not supported by the upstream response." }, 500);
  }

  const reader = response.body.getReader();
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      let buffer = new Uint8Array();
      const sendEvent = (payload) => {
        const line = `data: ${JSON.stringify(payload)}\n\n`;
        controller.enqueue(encoder.encode(line));
      };
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer = concatBytes(buffer, value);
          buffer = decodeEventStreamMessages(buffer, ({ headers, payload }) => {
            if (!payload || payload.length === 0) return;
            let parsed;
            try {
              parsed = JSON.parse(decoder.decode(payload));
            } catch (_) {
              parsed = null;
            }
            if (!parsed || typeof parsed !== "object") return;
            if (parsed.type) {
              sendEvent(parsed);
              return;
            }
            const eventType = headers[":event-type"] || headers["event-type"];
            if (eventType === "error") {
              sendEvent({ type: "error", error: parsed });
              return;
            }
            if (eventType && parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              sendEvent({ type: eventType, ...parsed });
              return;
            }
            sendEvent(parsed);
          });
        }
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      } finally {
        controller.close();
        try {
          reader.releaseLock();
        } catch (_) {
          // Ignore release errors.
        }
      }
    }
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: withCorsHeaders()
      });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "Use POST /chat or /google" }, 405);
    }

    const url = new URL(request.url);
    if (url.pathname === "/google") {
      const apiKey = env.GOOGLE_API_KEY;
      if (!apiKey) {
        return jsonResponse({
          error: "Missing Google API key. Set GOOGLE_API_KEY as a Worker secret."
        }, 500);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: "Invalid JSON body" }, 400);
      }

      const providedUserId = typeof body.userId === "string" ? body.userId.trim() : "";
      if (!providedUserId) {
        return jsonResponse({ error: "userId is required" }, 400);
      }

      const model = (body.model || "").trim();
      const payload = body.payload;
      if (!model || !payload || typeof payload !== "object") {
        return jsonResponse({ error: "model and payload are required" }, 400);
      }
      if (model !== "gemini-3-flash-preview") {
        return jsonResponse({ error: "Model not allowed" }, 403);
      }

      const useStreaming = body.stream === true;
      const endpoint = useStreaming
        ? `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse`
        : `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const responseText = await response.text();
        return jsonResponse({
          error: "Google request failed",
          status: response.status,
          body: responseText
        }, response.status);
      }

      if (useStreaming) {
        const headers = withCorsHeaders({
          "Content-Type": response.headers.get("content-type") || "text/event-stream"
        });
        return new Response(response.body, { status: response.status, headers });
      }

      const responseText = await response.text();
      const headers = withCorsHeaders({
        "Content-Type": response.headers.get("content-type") || "application/json"
      });
      return new Response(responseText, { status: response.status, headers });
    }

    if (url.pathname !== "/chat") {
      return jsonResponse({ error: "Not found" }, 404);
    }

    const accessKeyId = env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
    if (!accessKeyId || !secretAccessKey) {
      return jsonResponse({
        error: "Missing AWS credentials. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as Worker secrets."
      }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }

    const providedUserId = typeof body.userId === "string" ? body.userId.trim() : "";
    if (!providedUserId) {
      return jsonResponse({ error: "userId is required" }, 400);
    }
    const allowedUserId = typeof env.ALLOWED_USER_ID === "string" ? env.ALLOWED_USER_ID.trim() : "";
    if (!allowedUserId) {
      return jsonResponse({ error: "Paid worker user allowlist is not configured." }, 503);
    }
    if (providedUserId !== allowedUserId) {
      return jsonResponse({ error: "Unauthorized user" }, 403);
    }

    const region = (body.region || env.DEFAULT_REGION || "").trim();
    const modelId = (body.modelId || "").trim();
    const messages = body.messages;

    if (!region || !modelId || !Array.isArray(messages)) {
      return jsonResponse({ error: "region, modelId, and messages are required" }, 400);
    }

    const payload = {
      messages,
      inferenceConfig: body.inferenceConfig,
      system: body.system,
      toolConfig: body.toolConfig
    };

    const useStreaming = body.stream === true;
    const path = useStreaming ? `/model/${modelId}/converse-stream` : `/model/${modelId}/converse`;
    const bedrockUrl = `https://bedrock-runtime.${region}.amazonaws.com${path}`;

    const headers = new Headers({
      "host": `bedrock-runtime.${region}.amazonaws.com`
    });

    const bodyText = JSON.stringify(payload);

    const debug = body.debug === true;
    const signingDetails = await signRequest({
      method: "POST",
      url: bedrockUrl,
      headers,
      body: bodyText,
      accessKeyId,
      secretAccessKey,
      sessionToken: env.AWS_SESSION_TOKEN,
      region
    });

    headers.set("content-type", "application/json");
    headers.set("accept", useStreaming ? "application/vnd.amazon.eventstream" : "application/json");

    const response = await fetch(bedrockUrl, {
      method: "POST",
      headers,
      body: bodyText
    });

    if (useStreaming) {
      if (!response.ok) {
        const responseText = await response.text();
        return jsonResponse({
          error: "Bedrock request failed",
          status: response.status,
          body: responseText,
          debug: debug ? signingDetails : undefined
        }, response.status);
      }
      return streamBedrockResponse(response);
    }

    const responseText = await response.text();
    if (!response.ok) {
      return jsonResponse({
        error: "Bedrock request failed",
        status: response.status,
        body: responseText,
        debug: debug ? signingDetails : undefined
      }, response.status);
    }

    return new Response(responseText, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      }
    });
  }
};
