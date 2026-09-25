import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import type { Context, Next } from "hono";
import { JWT_SECRET, DEMO_API_KEY, findUserById } from "./store.js";

export interface LabJwtPayload extends JWTPayload {
  sub: string;
  username: string;
  role: string;
}

export async function issueJwt(
  userId: string,
  username: string,
  role: string,
  expiresInSeconds = 3600,
): Promise<string> {
  return new SignJWT({ username, role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .sign(JWT_SECRET);
}

export async function verifyJwt(token: string): Promise<LabJwtPayload> {
  const { payload } = await jwtVerify(token, JWT_SECRET);
  return payload as LabJwtPayload;
}

/**
 * VULN helper: decode JWT payload without verifying signature or alg.
 * Accepts alg:none / missing signature / forged claims — educational only.
 */
export function decodeJwtUnsafe(token: string): LabJwtPayload | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const payloadJson = Buffer.from(
      parts[1].replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    const payload = JSON.parse(payloadJson) as LabJwtPayload;
    if (!payload || typeof payload !== "object") return null;
    return payload;
  } catch {
    return null;
  }
}

/** Base64url-encode JSON (for forged unsigned tokens) */
export function b64urlJson(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/** Forge an unsigned alg:none JWT (educational demo helper) */
export function forgeUnsignedJwt(claims: {
  sub: string;
  username: string;
  role: string;
}): string {
  const header = b64urlJson({ alg: "none", typ: "JWT" });
  const payload = b64urlJson({
    ...claims,
    iat: Math.floor(Date.now() / 1000),
  });
  // Empty signature segment — classic alg:none shape
  return `${header}.${payload}.`;
}

/** Require X-API-Key: lab-demo-key */
export async function requireApiKey(c: Context, next: Next) {
  const key = c.req.header("X-API-Key");
  if (key !== DEMO_API_KEY) {
    return c.json(
      {
        error: "unauthorized",
        message:
          "有効な X-API-Key ヘッダーが必要です（デモキー: lab-demo-key）",
      },
      401,
    );
  }
  await next();
}

/** Require valid Bearer JWT; attach user to context */
export async function requireJwt(c: Context, next: Next) {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json(
      {
        error: "unauthorized",
        message: "Authorization: Bearer <JWT> が必要です",
      },
      401,
    );
  }
  const token = auth.slice(7);
  try {
    const payload = await verifyJwt(token);
    const user = findUserById(payload.sub!);
    if (!user) {
      return c.json({ error: "unauthorized", message: "ユーザーが見つかりません" }, 401);
    }
    c.set("jwt", payload);
    c.set("user", user);
    await next();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const expired = /expir|"exp"|timestamp check failed/i.test(msg);
    return c.json(
      {
        error: expired ? "token_expired" : "invalid_token",
        message: expired
          ? "JWT の有効期限が切れています（expiry 検証のデモ）"
          : `JWT 検証に失敗しました: ${msg}`,
      },
      401,
    );
  }
}
