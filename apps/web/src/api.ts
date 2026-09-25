/** Thin fetch helpers — uses Vite proxy (/api → :8787) in dev */

const BASE = import.meta.env.VITE_API_BASE ?? "";

export interface ApiResult {
  status: number;
  ok: boolean;
  data: unknown;
  headers: Record<string, string>;
}

export async function api(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: init.credentials ?? "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  let data: unknown;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });
  return { status: res.status, ok: res.ok, data, headers };
}

/** Client-side forge of alg:none JWT (mirrors server helper) */
export function forgeAlgNoneJwt(claims: {
  sub: string;
  username: string;
  role: string;
}): string {
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/=+$/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc({
    ...claims,
    iat: Math.floor(Date.now() / 1000),
  })}.`;
}
