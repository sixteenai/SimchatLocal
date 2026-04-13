const generateUuidV4 = (): string => crypto.randomUUID();

const isUuidV4 = (value: string): boolean =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const GOOGLE_VALID_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

const jsonResponse = (
  body: unknown,
  status = 200,
  { cacheControl = "no-store" }: { cacheControl?: string | null } = {},
): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...(cacheControl ? { "cache-control": cacheControl } : {}),
      ...corsHeaders,
    },
  });

const jsonError = (message: string, status = 400): Response =>
  jsonResponse({ error: message }, status, { cacheControl: null });

const normalizeId = (value: string | null | undefined): string => (value || "").trim();

const requireId = (value: string | null | undefined, message: string): string | Response => {
  const normalized = normalizeId(value);
  return normalized ? normalized : jsonError(message, 400);
};

async function parseJsonOrError(
  request: Request,
  logPrefix: string,
): Promise<[unknown | null, Response | null]> {
  try {
    const payload = await request.json();
    return [payload, null];
  } catch (error) {
    console.error(`${logPrefix}:`, error);
    return [null, jsonError("Invalid JSON body", 400)];
  }
}

const safeKeySegment = (value: string): string =>
  value.trim().replace(/[\s/]+/g, "_");

const buildPresetDataKey = (userId: string, presetId: string): string =>
  `presets/${safeKeySegment(userId)}/${safeKeySegment(presetId)}.json`;

const buildAvatarKey = (userId: string, presetId: string): string =>
  `presets/${safeKeySegment(userId)}/${safeKeySegment(presetId)}/avatar`;

const buildChatDataKey = (userId: string, chatId: string): string =>
  `chats/${safeKeySegment(userId)}/${safeKeySegment(chatId)}.json`;

const normalizeNumeric = (value: unknown): number | null => {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === "string") {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : null;
  }
  return null;
};

const extractChanges = (result: unknown): number => {
  if (!result || typeof result !== "object") return 0;
  if (typeof (result as any).changes === "number") {
    return (result as any).changes;
  }
  if (typeof (result as any).meta?.changes === "number") {
    return (result as any).meta.changes;
  }
  return 0;
};

const listR2KeysByPrefix = async (bucket: R2Bucket, prefix: string): Promise<string[]> => {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const listing = await bucket.list({ prefix, cursor });
    if (Array.isArray(listing.objects)) {
      listing.objects.forEach((entry) => {
        if (entry && typeof entry.key === "string") {
          keys.push(entry.key);
        }
      });
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
  return keys;
};

interface Env {
  SIMCHAT_D1: D1Database;
  DATA_BUCKET: R2Bucket;
  GOOGLE_CLIENT_ID?: string;
  DISCORD_FEEDBACK_WEBHOOK?: string;
}

interface GoogleJwk {
  kid?: string;
  n?: string;
  e?: string;
  kty?: string;
  alg?: string;
}

interface GoogleIdTokenHeader {
  alg?: string;
  kid?: string;
}

interface GoogleIdTokenPayload {
  sub?: string;
  email?: string;
  aud?: string | string[];
  iss?: string;
  exp?: number;
  iat?: number;
  email_verified?: boolean;
  name?: string;
}

const googleJwksCache: { keys: GoogleJwk[]; expiresAt: number } = { keys: [], expiresAt: 0 };
const base64UrlToString = (value: string): string => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return atob(padded);
};

const base64UrlToUint8Array = (value: string): Uint8Array => {
  const binary = base64UrlToString(value);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
};

const decodeBase64UrlJson = <T>(segment: string): T | null => {
  try {
    const decoded = base64UrlToString(segment);
    return JSON.parse(decoded) as T;
  } catch (_) {
    return null;
  }
};

const loadGoogleJwks = async (): Promise<GoogleJwk[]> => {
  const now = Date.now();
  if (googleJwksCache.expiresAt > now && googleJwksCache.keys.length) {
    return googleJwksCache.keys;
  }

  try {
    const response = await fetch(GOOGLE_JWKS_URL, {
      headers: { accept: "application/json" },
      cf: { cacheEverything: true, cacheTtl: 300 },
    });
    if (!response.ok) {
      throw new Error(`Google JWKS responded with status ${response.status}`);
    }
    const data = await response.json();
    if (data && Array.isArray(data.keys)) {
      googleJwksCache.keys = data.keys;
      googleJwksCache.expiresAt = now + GOOGLE_JWKS_CACHE_TTL_MS;
      return data.keys;
    }
  } catch (error) {
    console.error("Failed to load Google JWKS:", error);
  }

  return [];
};

const verifyGoogleIdToken = async (
  idToken: string,
  { expectedClientId }: { expectedClientId?: string },
): Promise<{ ok: true; payload: GoogleIdTokenPayload } | { ok: false; error: string }> => {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "Invalid Google token format" };
  }

  const header = decodeBase64UrlJson<GoogleIdTokenHeader>(parts[0]);
  const payload = decodeBase64UrlJson<GoogleIdTokenPayload>(parts[1]);

  if (!header || !payload) {
    return { ok: false, error: "Invalid Google token encoding" };
  }

  if (header.alg !== "RS256") {
    return { ok: false, error: "Unsupported Google token algorithm" };
  }

  if (!payload.sub) {
    return { ok: false, error: "Google token missing subject" };
  }

  if (!payload.iss || !GOOGLE_VALID_ISSUERS.has(payload.iss)) {
    return { ok: false, error: "Google token has invalid issuer" };
  }

  const audienceList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (expectedClientId && !audienceList.includes(expectedClientId)) {
    return { ok: false, error: "Google token audience mismatch" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < nowSeconds) {
    return { ok: false, error: "Google token has expired" };
  }

  if (payload.email_verified === false) {
    return { ok: false, error: "Google account email is not verified" };
  }

  const jwks = await loadGoogleJwks();
  const jwk = jwks.find((key) => key.kid && key.kid === header.kid);
  if (!jwk || !jwk.n || !jwk.e) {
    return { ok: false, error: "Unable to find Google signing key" };
  }

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      { ...jwk, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } catch (error) {
    console.error("Failed to import Google public key:", error);
    return { ok: false, error: "Unable to verify Google token" };
  }

  const encodedPayload = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToUint8Array(parts[2]);

  try {
    const verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      cryptoKey,
      signature,
      encodedPayload,
    );
    if (!verified) {
      return { ok: false, error: "Google token signature is invalid" };
    }
  } catch (error) {
    console.error("Failed to verify Google token signature:", error);
    return { ok: false, error: "Unable to verify Google token" };
  }

  return { ok: true, payload };
};

const worker: ExportedHandler<Env> = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const presetAvatarMatch = pathname.match(/^\/presets\/([^/]+)\/avatar\/?$/);
    const presetDetailMatch = pathname.match(/^\/presets\/([^/]+)\/?$/);
    const chatDetailMatch = pathname.match(/^\/chats\/([^/]+)\/?$/);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (pathname === "/auth/google" || pathname === "/auth/google/") {
      if (request.method === "POST") {
        return handleGoogleAuth(request, env);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (pathname === "/feedback" || pathname === "/feedback/") {
      if (request.method === "POST") {
        return handleFeedback(request, env);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (presetAvatarMatch) {
      const presetId = presetAvatarMatch[1];
      if (request.method === "GET") {
        return handlePresetAvatarFetch(request, env, presetId);
      }
      if (request.method === "POST" || request.method === "PUT") {
        return handlePresetAvatarUpload(request, env, presetId);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (presetDetailMatch) {
      const presetId = presetDetailMatch[1];
      if (request.method === "GET") {
        return handlePresetDetail(request, env, presetId);
      }
      if (request.method === "PUT") {
        return handlePresetUpdate(request, env, presetId);
      }
      if (request.method === "DELETE") {
        return handlePresetDelete(request, env, presetId);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (pathname === "/presets" || pathname === "/presets/") {
      if (request.method === "POST") {
        return handlePresetSave(request, env);
      }
      if (request.method === "GET") {
        return handlePresetList(request, env);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (chatDetailMatch) {
      const chatId = chatDetailMatch[1];
      if (request.method === "GET") {
        return handleChatDetail(request, env, chatId);
      }
      if (request.method === "DELETE") {
        return handleChatDelete(request, env, chatId);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (pathname === "/chats" || pathname === "/chats/") {
      if (request.method === "POST") {
        return handleChatSave(request, env);
      }
      if (request.method === "GET") {
        return handleChatList(request, env);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (pathname === "/account/delete" || pathname === "/account/delete/") {
      if (request.method === "POST") {
        return handleAccountDelete(request, env);
      }
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    const cookieId = generateUuidV4();
    return jsonResponse({ cookie: cookieId });
  },
};

export default worker;

async function handleFeedback(request: Request, env: Env): Promise<Response> {
  const [payload, parseError] = await parseJsonOrError(request, "Failed to parse feedback payload");
  if (parseError) return parseError;

  const message =
    payload && typeof (payload as any).message === "string" ? (payload as any).message.trim() : "";
  const emotion =
    payload && typeof (payload as any).emotion === "string" ? (payload as any).emotion.trim() : "";

  if (!message) {
    return jsonError("Feedback message is required", 400);
  }

  const emotionEmoji: Record<string, string> = {
    angry: "😡",
    sad: "😢",
    neutral: "😐",
    happy: "🙂",
    very_happy: "😄",
  };
  const emoji = emotion ? emotionEmoji[emotion] || "💬" : "💬";
  const safeMessage = message.length > 1800 ? `${message.slice(0, 1800)}…` : message;
  const discordBody = { content: `${emoji} ${safeMessage}` };
  const webhookUrl =
    typeof env.DISCORD_FEEDBACK_WEBHOOK === "string" ? env.DISCORD_FEEDBACK_WEBHOOK.trim() : "";

  if (!webhookUrl) {
    console.error("Missing DISCORD_FEEDBACK_WEBHOOK Worker secret");
    return jsonError("Feedback is not configured", 503);
  }

  let response: Response;
  try {
    response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(discordBody),
    });
  } catch (error) {
    console.error("Failed to send feedback to Discord:", error);
    return jsonError("Unable to send feedback", 502);
  }

  if (!response.ok) {
    let errorText = "";
    try {
      errorText = await response.text();
    } catch (_) {
      errorText = "";
    }
    console.error("Discord webhook error:", response.status, errorText);
    return jsonError("Unable to send feedback", 502);
  }

  return jsonResponse({ ok: true });
}

async function handleAccountDelete(request: Request, env: Env): Promise<Response> {
  const [payload, parseError] = await parseJsonOrError(
    request,
    "Failed to parse account delete payload",
  );
  if (parseError) return parseError;

  const userId =
    payload && typeof (payload as any).userId === "string"
      ? normalizeId((payload as any).userId)
      : "";

  if (!userId) {
    return jsonError("User ID is required", 400);
  }

  const r2Keys = new Set<string>();
  try {
    const { results: presetRows } = await env.SIMCHAT_D1.prepare(
      "SELECT r2_data_key, avatar_r2_key FROM presets_v2 WHERE user_id = ?1;",
    )
      .bind(userId)
      .all();

    if (Array.isArray(presetRows)) {
      presetRows.forEach((row) => {
        const dataKey = row && typeof (row as any).r2_data_key === "string" ? (row as any).r2_data_key : "";
        const avatarKey =
          row && typeof (row as any).avatar_r2_key === "string" ? (row as any).avatar_r2_key : "";
        if (dataKey) r2Keys.add(dataKey);
        if (avatarKey) r2Keys.add(avatarKey);
      });
    }

    const { results: chatRows } = await env.SIMCHAT_D1.prepare(
      "SELECT r2_data_key FROM chats_v2 WHERE user_id = ?1;",
    )
      .bind(userId)
      .all();

    if (Array.isArray(chatRows)) {
      chatRows.forEach((row) => {
        const dataKey = row && typeof (row as any).r2_data_key === "string" ? (row as any).r2_data_key : "";
        if (dataKey) r2Keys.add(dataKey);
      });
    }
  } catch (error) {
    console.error("Failed to gather account data keys:", error);
    return jsonError("Failed to load account data for deletion", 500);
  }

  try {
    const presetPrefix = `presets/${safeKeySegment(userId)}/`;
    const chatPrefix = `chats/${safeKeySegment(userId)}/`;
    const [presetKeys, chatKeys] = await Promise.all([
      listR2KeysByPrefix(env.DATA_BUCKET, presetPrefix),
      listR2KeysByPrefix(env.DATA_BUCKET, chatPrefix),
    ]);
    presetKeys.forEach((key) => r2Keys.add(key));
    chatKeys.forEach((key) => r2Keys.add(key));
  } catch (error) {
    console.error("Failed to list account data keys:", error);
  }

  let presetDeletes = 0;
  let chatDeletes = 0;
  let linkDeletes = 0;
  try {
    const presetDeleteResult = await env.SIMCHAT_D1.prepare(
      "DELETE FROM presets_v2 WHERE user_id = ?1;",
    )
      .bind(userId)
      .run();
    presetDeletes = extractChanges(presetDeleteResult);

    const chatDeleteResult = await env.SIMCHAT_D1.prepare(
      "DELETE FROM chats_v2 WHERE user_id = ?1;",
    )
      .bind(userId)
      .run();
    chatDeletes = extractChanges(chatDeleteResult);

    const linkDeleteResult = await env.SIMCHAT_D1.prepare(
      "DELETE FROM google_account_links WHERE linked_uuid = ?1;",
    )
      .bind(userId)
      .run();
    linkDeletes = extractChanges(linkDeleteResult);
  } catch (error) {
    console.error("Failed to delete account rows:", error);
    return jsonError("Failed to delete account data", 500);
  }

  let r2Deleted = 0;
  if (r2Keys.size) {
    try {
      const keys = Array.from(r2Keys);
      await env.DATA_BUCKET.delete(keys);
      r2Deleted = keys.length;
    } catch (error) {
      console.error("Failed to delete account data from R2:", error);
    }
  }

  return jsonResponse({
    deleted: {
      presets: presetDeletes,
      chats: chatDeletes,
      google_links: linkDeletes,
      r2_objects: r2Deleted,
    },
  });
}

async function handleGoogleAuth(request: Request, env: Env): Promise<Response> {
  const [payload, parseError] = await parseJsonOrError(
    request,
    "Failed to parse Google authentication payload",
  );
  if (parseError) return parseError;

  const credential =
    payload && typeof (payload as any).credential === "string"
      ? (payload as any).credential.trim()
      : "";
  const providedUserId =
    payload && typeof (payload as any).userId === "string"
      ? normalizeId((payload as any).userId)
      : "";

  if (!credential) {
    return jsonError("Google credential is required", 400);
  }

  if (!env.GOOGLE_CLIENT_ID) {
    console.error("Missing GOOGLE_CLIENT_ID environment variable for Google verification");
    return jsonError("Google authentication is not configured", 500);
  }

  const verification = await verifyGoogleIdToken(credential, {
    expectedClientId: env.GOOGLE_CLIENT_ID,
  });
  if (!verification.ok) {
    return jsonError(verification.error || "Google authentication failed", 401);
  }

  const googleSub = verification.payload.sub || "";
  const googleEmail =
    verification.payload.email && typeof verification.payload.email === "string"
      ? verification.payload.email.trim()
      : null;
  const emailVerified = verification.payload.email_verified === true;
  let linkedUserId = providedUserId || generateUuidV4();
  let isNewLink = false;

  try {
    const existingRow = await env.SIMCHAT_D1.prepare(
      "SELECT linked_uuid, google_email FROM google_account_links WHERE google_sub = ?1;",
    )
      .bind(googleSub)
      .first<Readonly<Record<string, unknown>>>();

    const existingLinkedUuid =
      existingRow && typeof existingRow.linked_uuid === "string"
        ? (existingRow.linked_uuid as string).trim()
        : "";
    const existingEmail =
      existingRow && typeof existingRow.google_email === "string"
        ? (existingRow.google_email as string).trim()
        : "";

    if (existingLinkedUuid) {
      linkedUserId = existingLinkedUuid;
      if (googleEmail && googleEmail !== existingEmail) {
        await env.SIMCHAT_D1.prepare(
          "UPDATE google_account_links SET google_email = ?2 WHERE google_sub = ?1;",
        )
          .bind(googleSub, googleEmail)
          .run();
      }
    } else {
      const insertResult = await env.SIMCHAT_D1.prepare(
        "INSERT INTO google_account_links (google_sub, google_email, linked_uuid) VALUES (?1, ?2, ?3);",
      )
        .bind(googleSub, googleEmail, linkedUserId)
        .run();

      isNewLink = extractChanges(insertResult) > 0;
      if (!isNewLink) {
        const row = await env.SIMCHAT_D1.prepare(
          "SELECT linked_uuid, google_email FROM google_account_links WHERE google_sub = ?1;",
        )
          .bind(googleSub)
          .first<Readonly<Record<string, unknown>>>();
        const fallbackUserId =
          row && typeof row.linked_uuid === "string" ? (row.linked_uuid as string).trim() : "";
        if (fallbackUserId) {
          linkedUserId = fallbackUserId;
        }
      }
    }
  } catch (error) {
    console.error("Failed to link Google account to user:", error);
    return jsonError("Failed to link Google account", 500);
  }

  return jsonResponse({
    user_id: linkedUserId,
    google_sub: googleSub,
    google_email: googleEmail,
    email_verified: emailVerified,
    is_new_link: isNewLink,
  });
}

async function putJsonInR2(bucket: R2Bucket, key: string, data: string) {
  await bucket.put(key, data, {
    httpMetadata: { contentType: "application/json" },
  });
}

async function handlePresetAvatarUpload(
  request: Request,
  env: Env,
  presetId: string,
): Promise<Response> {
  const normalizedPresetId = normalizeId(presetId);
  const url = new URL(request.url);
  const userId = requireId(url.searchParams.get("userId"), "User ID is required to upload a preset image");

  if (!normalizedPresetId) {
    return jsonError("Preset ID is required", 400);
  }

  if (userId instanceof Response) return userId;

  const rawContentType = request.headers.get("content-type") || "";
  const contentType = rawContentType.split(";")[0].trim();
  if (!contentType || !contentType.startsWith("image/")) {
    return jsonError("Image content-type is required (e.g. image/png)", 415);
  }

  const body = await request.arrayBuffer();
  if (!body.byteLength) {
    return jsonError("Image body is empty", 400);
  }

  if (body.byteLength > MAX_AVATAR_BYTES) {
    return jsonError("Image is too large (max 5MB)", 413);
  }

  let avatarKey: string | null = null;
  try {
    const row = await env.SIMCHAT_D1.prepare(
      "SELECT user_id, avatar_r2_key FROM presets_v2 WHERE preset_id = ?1;",
    )
      .bind(normalizedPresetId)
      .first<Readonly<Record<string, unknown>>>();

    const ownerId = row && typeof row.user_id === "string" ? (row.user_id as string) : "";
    if (!ownerId) {
      return jsonError("Preset not found", 404);
    }
    if (ownerId !== userId) {
      return jsonError("Preset belongs to a different user", 403);
    }

    const previousAvatarKey =
      row && typeof row.avatar_r2_key === "string" ? (row.avatar_r2_key as string) : null;
    avatarKey = buildAvatarKey(userId, normalizedPresetId);

    await env.DATA_BUCKET.put(avatarKey, body, {
      httpMetadata: { contentType },
      customMetadata: {
        presetId: normalizedPresetId,
        userId,
      },
    });

    const updatedAt = new Date().toISOString();
    const result = await env.SIMCHAT_D1.prepare(
      `
        UPDATE presets_v2
        SET avatar_r2_key = ?2,
            updated_at = ?3
        WHERE preset_id = ?1 AND user_id = ?4;
      `,
    )
      .bind(normalizedPresetId, avatarKey, updatedAt, userId)
      .run();

    if (!extractChanges(result)) {
      try {
        await env.DATA_BUCKET.delete(avatarKey);
      } catch (cleanupError) {
        console.warn("Failed to remove uploaded avatar after missing preset:", cleanupError);
      }
      return jsonError("Preset not found or not owned by user", 404);
    }

    if (previousAvatarKey && previousAvatarKey !== avatarKey) {
      try {
        await env.DATA_BUCKET.delete(previousAvatarKey);
      } catch (cleanupError) {
        console.warn("Failed to remove previous avatar from R2:", cleanupError);
      }
    }

    return jsonResponse({
      preset_id: normalizedPresetId,
      avatar_r2_key: avatarKey,
      updated_at: updatedAt,
    });
  } catch (error) {
    console.error("Failed to upload preset image:", error);
    if (avatarKey) {
      try {
        await env.DATA_BUCKET.delete(avatarKey);
      } catch (cleanupError) {
        console.warn("Failed to remove uploaded avatar after error:", cleanupError);
      }
    }
    return jsonError("Failed to upload preset image", 500);
  }
}

async function handlePresetAvatarFetch(
  request: Request,
  env: Env,
  presetId: string,
): Promise<Response> {
  const normalizedPresetId = normalizeId(presetId);
  const url = new URL(request.url);
  const userId = requireId(url.searchParams.get("userId"), "User ID is required to load preset image");

  if (!normalizedPresetId) {
    return jsonError("Preset ID is required", 400);
  }

  if (userId instanceof Response) return userId;

  try {
    const row = await env.SIMCHAT_D1.prepare(
      "SELECT user_id, avatar_r2_key FROM presets_v2 WHERE preset_id = ?1;",
    )
      .bind(normalizedPresetId)
      .first<Readonly<Record<string, unknown>>>();

    const ownerId = row && typeof row.user_id === "string" ? (row.user_id as string) : "";
    if (!ownerId) {
      return jsonError("Preset not found", 404);
    }
    if (ownerId !== userId) {
      return jsonError("Preset belongs to a different user", 403);
    }

    const avatarKey =
      row && typeof row.avatar_r2_key === "string" ? (row.avatar_r2_key as string) : null;
    if (!avatarKey) {
      return jsonError("Preset image not found", 404);
    }

    const obj = await env.DATA_BUCKET.get(avatarKey);
    if (!obj) {
      return jsonError("Preset image not found", 404);
    }

    const headers = new Headers({
      ...corsHeaders,
      "cache-control": "private, max-age=300",
      "content-type": "application/octet-stream",
    });
    if (typeof obj.writeHttpMetadata === "function") {
      obj.writeHttpMetadata(headers);
    }
    return new Response(obj.body, {
      status: 200,
      headers,
    });
  } catch (error) {
    console.error("Failed to load preset image:", error);
    return jsonError("Failed to load preset image", 500);
  }
}

async function handlePresetSave(request: Request, env: Env): Promise<Response> {
  const [payload, parseError] = await parseJsonOrError(
    request,
    "Failed to parse preset save request body",
  );
  if (parseError) return parseError;

  const presetName =
    payload && typeof (payload as any).presetName === "string"
      ? (payload as any).presetName.trim()
      : "";
  const userId =
    payload && typeof (payload as any).userId === "string"
      ? (payload as any).userId.trim()
      : "";
  const data =
    payload && typeof (payload as any).data !== "undefined" ? (payload as any).data : null;
  const description =
    payload && typeof (payload as any).description === "string"
      ? (payload as any).description.trim()
      : null;
  const avatarSourcePresetId =
    payload && typeof (payload as any).avatarSourcePresetId === "string"
      ? normalizeId((payload as any).avatarSourcePresetId)
      : null;

  if (!presetName) {
    return jsonError("Preset name is required", 400);
  }

  if (!userId) {
    return jsonError("User ID is required", 400);
  }

  if (data === null || typeof data === "undefined") {
    return jsonError("Preset data is required", 400);
  }

  const presetId = generateUuidV4();
  const createdAt = new Date().toISOString();
  const serializedData = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  const estimatedTokenCountRaw =
    data && typeof (data as any).estimatedTokenCount !== "undefined"
      ? (data as any).estimatedTokenCount
      : null;
  const estimatedTokenCount = normalizeNumeric(estimatedTokenCountRaw);

  const dataKey = buildPresetDataKey(userId, presetId);
  let avatarKey: string | null = null;
  try {
    if (avatarSourcePresetId) {
      avatarKey = await copyPresetAvatarIfPresent(env, {
        sourcePresetId: avatarSourcePresetId,
        targetPresetId: presetId,
        userId,
      });
    }
    await putJsonInR2(env.DATA_BUCKET, dataKey, serializedData);
    await env.SIMCHAT_D1.prepare(
      `
        INSERT INTO presets_v2 (
          preset_id,
          user_id,
          preset_name,
          description,
          created_at,
          updated_at,
          estimated_token_count,
          r2_data_key,
          avatar_r2_key
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);
      `,
    )
      .bind(
        presetId,
        userId,
        presetName,
        description,
        createdAt,
        null,
        estimatedTokenCount,
        dataKey,
        avatarKey,
      )
      .run();
  } catch (error) {
    console.error("Failed to persist preset:", error);
    try {
      await env.DATA_BUCKET.delete(dataKey);
    } catch (_) {
      // best-effort cleanup
    }
    if (avatarKey) {
      try {
        await env.DATA_BUCKET.delete(avatarKey);
      } catch (_) {
        // best-effort cleanup
      }
    }
    return jsonError("Failed to save preset", 500);
  }

  return jsonResponse(
    {
      preset_id: presetId,
      user_id: userId,
      preset_name: presetName,
      description,
      created_at: createdAt,
      updated_at: null,
      estimated_token_count: estimatedTokenCount,
      avatar_r2_key: avatarKey,
    },
    201,
  );
}

async function copyPresetAvatarIfPresent(
  env: Env,
  {
    sourcePresetId,
    targetPresetId,
    userId,
  }: { sourcePresetId: string; targetPresetId: string; userId: string },
): Promise<string | null> {
  const normalizedSource = normalizeId(sourcePresetId);
  if (!normalizedSource) return null;

  const row = await env.SIMCHAT_D1.prepare(
    "SELECT user_id, avatar_r2_key FROM presets_v2 WHERE preset_id = ?1;",
  )
    .bind(normalizedSource)
    .first<Readonly<Record<string, unknown>>>();

  const ownerId = row && typeof row.user_id === "string" ? (row.user_id as string) : "";
  if (!ownerId || ownerId !== userId) {
    return null;
  }

  const sourceKey =
    row && typeof row.avatar_r2_key === "string" ? (row.avatar_r2_key as string) : null;
  if (!sourceKey) return null;

  const sourceObj = await env.DATA_BUCKET.get(sourceKey);
  if (!sourceObj) return null;

  const targetKey = buildAvatarKey(userId, targetPresetId);
  const body = await sourceObj.arrayBuffer();
  const contentType = sourceObj.httpMetadata?.contentType || "application/octet-stream";

  await env.DATA_BUCKET.put(targetKey, body, {
    httpMetadata: { contentType },
    customMetadata: {
      userId,
      presetId: targetPresetId,
      clonedFromPresetId: normalizedSource,
    },
  });

  return targetKey;
}

async function handlePresetUpdate(
  request: Request,
  env: Env,
  presetId: string,
): Promise<Response> {
  const normalizedPresetId = normalizeId(presetId);
  if (!normalizedPresetId) {
    return jsonError("Preset ID is required", 400);
  }

  const [payload, parseError] = await parseJsonOrError(
    request,
    "Failed to parse preset update request body",
  );
  if (parseError) return parseError;

  const presetName =
    payload && typeof (payload as any).presetName === "string"
      ? (payload as any).presetName.trim()
      : "";
  const userId =
    payload && typeof (payload as any).userId === "string"
      ? (payload as any).userId.trim()
      : "";
  const data =
    payload && typeof (payload as any).data !== "undefined" ? (payload as any).data : null;
  const description =
    payload && typeof (payload as any).description === "string"
      ? (payload as any).description.trim()
      : null;

  if (!presetName) {
    return jsonError("Preset name is required", 400);
  }

  if (!userId) {
    return jsonError("User ID is required", 400);
  }

  if (data === null || typeof data === "undefined") {
    return jsonError("Preset data is required", 400);
  }

  try {
    const existing = await env.SIMCHAT_D1.prepare(
      "SELECT user_id, created_at, r2_data_key, avatar_r2_key FROM presets_v2 WHERE preset_id = ?1;",
    )
      .bind(normalizedPresetId)
      .first<Readonly<Record<string, unknown>>>();

    const existingUserId =
      existing && typeof existing.user_id === "string" ? (existing.user_id as string) : "";
    const existingCreatedAt =
      existing && typeof existing.created_at === "string"
        ? (existing.created_at as string)
        : new Date().toISOString();
    const existingR2Key =
      existing && typeof existing.r2_data_key === "string" ? (existing.r2_data_key as string) : "";
    const existingAvatarKey =
      existing && typeof existing.avatar_r2_key === "string"
        ? (existing.avatar_r2_key as string)
        : null;

    if (!existingUserId) {
      return jsonError("Preset not found", 404);
    }

    if (existingUserId !== userId) {
      return jsonError("Preset belongs to a different user", 403);
    }

    const r2Key = existingR2Key || buildPresetDataKey(userId, normalizedPresetId);
    const serializedData = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    const estimatedTokenCountRaw =
      data && typeof (data as any).estimatedTokenCount !== "undefined"
        ? (data as any).estimatedTokenCount
        : null;
    const estimatedTokenCount = normalizeNumeric(estimatedTokenCountRaw);

    await putJsonInR2(env.DATA_BUCKET, r2Key, serializedData);

    const updatedAt = new Date().toISOString();
    const result = await env.SIMCHAT_D1.prepare(
      `
        UPDATE presets_v2
        SET preset_name = ?2,
            description = ?3,
            updated_at = ?4,
            estimated_token_count = ?5,
            r2_data_key = ?6
        WHERE preset_id = ?1 AND user_id = ?7;
      `,
    )
      .bind(
        normalizedPresetId,
        presetName,
        description,
        updatedAt,
        estimatedTokenCount,
        r2Key,
        userId,
      )
      .run();

    if (!extractChanges(result)) {
      return jsonError("Preset not found or not owned by user", 404);
    }

    return jsonResponse({
      preset_id: normalizedPresetId,
      user_id: userId,
      preset_name: presetName,
      description,
      created_at: existingCreatedAt,
      updated_at: updatedAt,
      estimated_token_count: estimatedTokenCount,
      avatar_r2_key: existingAvatarKey,
    });
  } catch (error) {
    console.error("Failed to update preset:", error);
    return jsonError("Failed to update preset", 500);
  }
}

async function handlePresetList(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const userId = requireId(
    url.searchParams.get("userId"),
    "User ID is required to list presets",
  );
  if (userId instanceof Response) return userId;

  try {
    const { results } = await env.SIMCHAT_D1.prepare(
      `
        SELECT
          preset_id,
          user_id,
          preset_name,
          description,
          created_at,
          updated_at,
          estimated_token_count,
          avatar_r2_key
        FROM presets_v2
        WHERE user_id = ?1
        ORDER BY datetime(created_at) DESC;
      `,
    )
      .bind(userId)
      .all();

    const normalized = Array.isArray(results)
      ? results.map((row) => ({
          preset_id: (row as any).preset_id,
          user_id: (row as any).user_id,
          preset_name: (row as any).preset_name,
          description: (row as any).description ?? null,
          created_at: (row as any).created_at,
          updated_at: (row as any).updated_at ?? null,
          estimated_token_count: normalizeNumeric((row as any).estimated_token_count),
          avatar_r2_key: (row as any).avatar_r2_key ?? null,
        }))
      : [];

    return jsonResponse({ presets: normalized });
  } catch (error) {
    console.error("Failed to load presets:", error);
    return jsonError("Failed to load presets for user", 500);
  }
}

async function handlePresetDetail(
  request: Request,
  env: Env,
  presetId: string,
): Promise<Response> {
  const normalizedPresetId = normalizeId(presetId);
  const url = new URL(request.url);
  const userId = requireId(url.searchParams.get("userId"), "User ID is required");

  if (!normalizedPresetId) {
    return jsonError("Preset ID is required", 400);
  }

  if (userId instanceof Response) return userId;

  try {
    const row = await env.SIMCHAT_D1.prepare(
      `
        SELECT
          preset_id,
          user_id,
          preset_name,
          description,
          created_at,
          updated_at,
          estimated_token_count,
          r2_data_key,
          avatar_r2_key
        FROM presets_v2
        WHERE preset_id = ?1 AND user_id = ?2
        LIMIT 1;
      `,
    )
      .bind(normalizedPresetId, userId)
      .first<Readonly<Record<string, unknown>>>();

    if (!row) {
      return jsonError("Preset not found", 404);
    }

    const r2Key = typeof (row as any).r2_data_key === "string" ? (row as any).r2_data_key : "";
    if (!r2Key) {
      return jsonError("Preset storage is missing", 500);
    }

    const obj = await env.DATA_BUCKET.get(r2Key);
    if (!obj) {
      return jsonError("Preset data not found", 404);
    }
    const rawData = await obj.text();
    let parsedData: unknown = rawData;
    try {
      parsedData = JSON.parse(rawData);
    } catch (_) {
      parsedData = rawData;
    }
    const estimatedTokenCount = normalizeNumeric((row as any).estimated_token_count);

    return jsonResponse({
      preset_id: row.preset_id,
      user_id: row.user_id,
      preset_name: row.preset_name,
      description: row.description ?? null,
      created_at: row.created_at,
      updated_at: row.updated_at ?? null,
      estimated_token_count: estimatedTokenCount,
      avatar_r2_key: (row as any).avatar_r2_key ?? null,
      data: parsedData,
    });
  } catch (error) {
    console.error("Failed to load preset:", error);
    return jsonError("Failed to load preset", 500);
  }
}

async function handlePresetDelete(
  request: Request,
  env: Env,
  presetId: string,
): Promise<Response> {
  const normalizedPresetId = normalizeId(presetId);
  const url = new URL(request.url);
  const userId = requireId(
    url.searchParams.get("userId"),
    "User ID is required to delete a preset",
  );

  if (!normalizedPresetId) {
    return jsonError("Preset ID is required to delete a preset", 400);
  }

  if (userId instanceof Response) return userId;

  try {
    const row = await env.SIMCHAT_D1.prepare(
      "SELECT r2_data_key, avatar_r2_key FROM presets_v2 WHERE preset_id = ?1 AND user_id = ?2;",
    )
      .bind(normalizedPresetId, userId)
      .first<Readonly<Record<string, unknown>>>();

    if (!row) {
      return jsonError("Preset not found or not owned by user", 404);
    }

    const dataKey = typeof row.r2_data_key === "string" ? (row.r2_data_key as string) : null;
    const avatarKey = typeof row.avatar_r2_key === "string" ? (row.avatar_r2_key as string) : null;

    try {
      if (dataKey) {
        await env.DATA_BUCKET.delete(dataKey);
      }
      if (avatarKey) {
        await env.DATA_BUCKET.delete(avatarKey);
      }
    } catch (cleanupError) {
      console.warn("Failed to remove preset objects from R2:", cleanupError);
    }

    const result = await env.SIMCHAT_D1.prepare(
      "DELETE FROM presets_v2 WHERE preset_id = ?1 AND user_id = ?2;",
    )
      .bind(normalizedPresetId, userId)
      .run();

    if (!extractChanges(result)) {
      return jsonError("Preset not found or not owned by user", 404);
    }

    return jsonResponse({ success: true });
  } catch (error) {
    console.error("Failed to delete preset:", error);
    return jsonError("Failed to delete preset for user", 500);
  }
}

async function handleChatSave(request: Request, env: Env): Promise<Response> {
  const [payload, parseError] = await parseJsonOrError(
    request,
    "Failed to parse chat save request body",
  );
  if (parseError) return parseError;

  const userId =
    payload && typeof (payload as any).userId === "string"
      ? (payload as any).userId.trim()
      : "";
  const chatIdRaw =
    payload && typeof (payload as any).chatId === "string"
      ? (payload as any).chatId.trim()
      : "";
  const title =
    payload && typeof (payload as any).title === "string"
      ? (payload as any).title.trim()
      : "";
  const data =
    payload && typeof (payload as any).data !== "undefined" ? (payload as any).data : null;
  const presetId =
    payload && typeof (payload as any).presetId === "string"
      ? (payload as any).presetId.trim()
      : "";

  if (!userId) {
    return jsonError("User ID is required", 400);
  }

  if (!presetId) {
    return jsonError("Preset ID is required to save a chat", 400);
  }

  if (data === null || typeof data === "undefined") {
    return jsonError("Chat data is required", 400);
  }

  const chatId = chatIdRaw || generateUuidV4();
  const now = new Date().toISOString();
  let createdAt = now;
  const serializedData = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  const requestedTitle = title;
  let normalizedTitle = requestedTitle || chatId;
  const lastTokenCountRaw =
    data && typeof (data as any).lastTokenCount !== "undefined"
      ? (data as any).lastTokenCount
      : null;
  const lastTokenCount = normalizeNumeric(lastTokenCountRaw);
  const messageCount =
    Array.isArray((data as any)?.entries) && (data as any).entries.length
      ? (data as any).entries.length
      : null;

  try {
    const presetRow = await env.SIMCHAT_D1.prepare(
      "SELECT preset_id FROM presets_v2 WHERE preset_id = ?1 AND user_id = ?2;",
    )
      .bind(presetId, userId)
      .first<Readonly<Record<string, unknown>>>();

    if (!presetRow) {
      return jsonError("Preset not found for user", 404);
    }

    const existing = await env.SIMCHAT_D1.prepare(
      "SELECT user_id, created_at, title, r2_data_key FROM chats_v2 WHERE chat_id = ?1;",
    )
      .bind(chatId)
      .first<Readonly<Record<string, unknown>>>();

    const existingUserId =
      existing && typeof existing.user_id === "string"
        ? (existing.user_id as string)
        : "";
    const existingCreatedAt =
      existing && typeof existing.created_at === "string"
        ? (existing.created_at as string)
        : null;
    const existingTitle =
      existing && typeof (existing as any).title === "string"
        ? String((existing as any).title).trim()
        : "";
    const existingR2Key =
      existing && typeof existing.r2_data_key === "string" ? (existing.r2_data_key as string) : "";

    if (existingUserId && existingUserId !== userId) {
      return jsonError("Chat belongs to a different user", 403);
    }

    const shouldIgnoreRequestedTitle =
      !requestedTitle ||
      (requestedTitle === chatId && isUuidV4(requestedTitle) && existingTitle && existingTitle !== requestedTitle);
    normalizedTitle = shouldIgnoreRequestedTitle ? (existingTitle || chatId) : requestedTitle;

    const r2Key = existingR2Key || buildChatDataKey(userId, chatId);
    await putJsonInR2(env.DATA_BUCKET, r2Key, serializedData);

    if (existingCreatedAt) {
      createdAt = existingCreatedAt;
      await env.SIMCHAT_D1.prepare(
        `
          UPDATE chats_v2
          SET title = ?2,
              preset_id = ?3,
              last_used = ?4,
              message_count = ?5,
              last_token_count = ?6,
              r2_data_key = ?7
          WHERE chat_id = ?1 AND user_id = ?8;
        `,
      )
        .bind(
          chatId,
          normalizedTitle,
          presetId,
          now,
          messageCount,
          lastTokenCount,
          r2Key,
          userId,
        )
        .run();
    } else {
      await env.SIMCHAT_D1.prepare(
        `
          INSERT INTO chats_v2 (
            chat_id,
            user_id,
            preset_id,
            title,
            created_at,
            last_used,
            message_count,
            last_token_count,
            r2_data_key
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);
        `,
      )
        .bind(
          chatId,
          userId,
          presetId,
          normalizedTitle,
          createdAt,
          now,
          messageCount,
          lastTokenCount,
          r2Key,
        )
        .run();
    }
  } catch (error) {
    console.error("Failed to persist chat:", error);
    return jsonError("Failed to save chat", 500);
  }

  return jsonResponse(
    {
      chat_id: chatId,
      user_id: userId,
      preset_id: presetId,
      title: normalizedTitle,
      created_at: createdAt,
      last_used: now,
      message_count: messageCount,
      last_token_count: lastTokenCount,
    },
    201,
  );
}

async function handleChatList(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const userId = requireId(url.searchParams.get("userId"), "User ID is required to list chats");
  if (userId instanceof Response) return userId;

  try {
    const { results } = await env.SIMCHAT_D1.prepare(
      `
        SELECT
          chat_id,
          user_id,
          preset_id,
          title,
          created_at,
          last_used,
          message_count,
          last_token_count
        FROM chats_v2
        WHERE user_id = ?1
        ORDER BY datetime(last_used) DESC, datetime(created_at) DESC;
      `,
    )
      .bind(userId)
      .all();

    const normalized = Array.isArray(results)
      ? results.map((row) => ({
          chat_id: (row as any).chat_id,
          user_id: (row as any).user_id,
          preset_id: (row as any).preset_id,
          title: (row as any).title,
          created_at: (row as any).created_at,
          last_used: (row as any).last_used,
          message_count: normalizeNumeric((row as any).message_count),
          last_token_count: normalizeNumeric((row as any).last_token_count),
        }))
      : [];

    return jsonResponse({ chats: normalized });
  } catch (error) {
    console.error("Failed to load chats:", error);
    return jsonError("Failed to load chats for user", 500);
  }
}

async function handleChatDetail(
  request: Request,
  env: Env,
  chatId: string,
): Promise<Response> {
  const normalizedChatId = normalizeId(chatId);
  const url = new URL(request.url);
  const userId = requireId(
    url.searchParams.get("userId"),
    "User ID is required to load a chat",
  );
  const touchParam = url.searchParams.get("touch");
  const shouldTouchLastUsed = (() => {
    if (touchParam === null) return true;
    const value = touchParam.trim().toLowerCase();
    if (!value) return true;
    return !["0", "false", "no", "off"].includes(value);
  })();

  if (!normalizedChatId) {
    return jsonError("Chat ID is required", 400);
  }

  if (userId instanceof Response) return userId;

  try {
    const row = await env.SIMCHAT_D1.prepare(
      `
        SELECT
          chat_id,
          user_id,
          preset_id,
          title,
          created_at,
          last_used,
          message_count,
          last_token_count,
          r2_data_key
        FROM chats_v2
        WHERE chat_id = ?1 AND user_id = ?2
        LIMIT 1;
      `,
    )
      .bind(normalizedChatId, userId)
      .first<Readonly<Record<string, unknown>>>();

    if (!row) {
      return jsonError("Chat not found", 404);
    }

    const r2Key = typeof (row as any).r2_data_key === "string" ? (row as any).r2_data_key : "";
    if (!r2Key) {
      return jsonError("Chat storage is missing", 500);
    }

    const obj = await env.DATA_BUCKET.get(r2Key);
    if (!obj) {
      return jsonError("Chat data not found", 404);
    }

    const rawData = await obj.text();
    let parsedData: unknown = rawData;
    try {
      parsedData = JSON.parse(rawData);
    } catch (_) {
      parsedData = rawData;
    }

    const lastTokenCount = (() => {
      if (parsedData && typeof parsedData === "object") {
        const raw =
          (parsedData as any).lastTokenCount ??
          (parsedData as any).last_token_count ??
          null;
        return normalizeNumeric(raw);
      }
      return null;
    })();

    const storedLastUsed =
      typeof (row as any).last_used === "string" ? String((row as any).last_used) : null;
    const lastUsed = shouldTouchLastUsed ? new Date().toISOString() : storedLastUsed;

    if (shouldTouchLastUsed) {
      await env.SIMCHAT_D1.prepare(
        "UPDATE chats_v2 SET last_used = ?2 WHERE chat_id = ?1 AND user_id = ?3;",
      )
        .bind(normalizedChatId, lastUsed, userId)
        .run();
    }

    return jsonResponse({
      chat_id: row.chat_id,
      user_id: row.user_id,
      preset_id: row.preset_id,
      title: row.title,
      created_at: row.created_at,
      last_used: lastUsed,
      message_count: normalizeNumeric((row as any).message_count),
      last_token_count: lastTokenCount,
      data: parsedData,
    });
  } catch (error) {
    console.error("Failed to load chat:", error);
    return jsonError("Failed to load chat", 500);
  }
}

async function handleChatDelete(
  request: Request,
  env: Env,
  chatId: string,
): Promise<Response> {
  const normalizedChatId = normalizeId(chatId);
  const url = new URL(request.url);
  const userId = requireId(
    url.searchParams.get("userId"),
    "User ID is required to delete a chat",
  );

  if (!normalizedChatId) {
    return jsonError("Chat ID is required to delete a chat", 400);
  }

  if (userId instanceof Response) return userId;

  try {
    const row = await env.SIMCHAT_D1.prepare(
      "SELECT r2_data_key FROM chats_v2 WHERE chat_id = ?1 AND user_id = ?2;",
    )
      .bind(normalizedChatId, userId)
      .first<Readonly<Record<string, unknown>>>();

    if (!row) {
      return jsonError("Chat not found or not owned by user", 404);
    }

    const r2Key = typeof row.r2_data_key === "string" ? (row.r2_data_key as string) : null;

    try {
      if (r2Key) {
        await env.DATA_BUCKET.delete(r2Key);
      }
    } catch (cleanupError) {
      console.warn("Failed to remove chat object from R2:", cleanupError);
    }

    const result = await env.SIMCHAT_D1.prepare(
      "DELETE FROM chats_v2 WHERE chat_id = ?1 AND user_id = ?2;",
    )
      .bind(normalizedChatId, userId)
      .run();

    if (!extractChanges(result)) {
      return jsonError("Chat not found or not owned by user", 404);
    }

    return jsonResponse({ success: true });
  } catch (error) {
    console.error("Failed to delete chat:", error);
    return jsonError("Failed to delete chat for user", 500);
  }
}
