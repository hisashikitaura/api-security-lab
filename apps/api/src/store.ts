/**
 * In-memory seed store for the API security lab.
 * Educational only — resets on every process restart.
 */

export type Role = "user" | "admin";

export interface User {
  id: string;
  username: string;
  password: string; // demo plaintext — never do this in production
  displayName: string;
  role: Role;
}

export interface Note {
  id: string;
  ownerId: string;
  title: string;
  body: string;
}

export interface Order {
  id: string;
  ownerId: string;
  item: string;
  amount: number;
}

export interface Profile {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  bio: string;
}

/** Cookie-based CSRF demo session */
export interface CsrfSession {
  sessionId: string;
  userId: string;
  username: string;
  csrfToken: string;
  balance: number;
}

export const DEMO_API_KEY = "lab-demo-key";
/** Server-only secret — never expose via VITE_ env */
export const SERVER_SECRET = "server-only-lab-secret-do-not-put-in-vite";
export const JWT_SECRET = new TextEncoder().encode(
  "lab-jwt-signing-secret-demo-only",
);
export const RATE_LIMIT_MAX = 5;
export const RATE_LIMIT_WINDOW_MS = 10_000;

export const SESSION_COOKIE = "lab_session";
export const CSRF_HEADER = "X-CSRF-Token";

export const users: User[] = [
  {
    id: "u-alice",
    username: "alice",
    password: "alice123",
    displayName: "Alice",
    role: "user",
  },
  {
    id: "u-bob",
    username: "bob",
    password: "bob123",
    displayName: "Bob",
    role: "user",
  },
];

const NOTES_SEED: Note[] = [
  {
    id: "n-alice-1",
    ownerId: "u-alice",
    title: "Aliceの秘密メモ",
    body: "明日の会議は午前10時。パスワードはここに書かないこと。",
  },
  {
    id: "n-bob-1",
    ownerId: "u-bob",
    title: "Bobの秘密メモ",
    body: "銀行口座のメモ（デモ）。Aliceには見せたくない内容です。",
  },
];

/** Mutable notes for write-side IDOR demos */
export let notes: Note[] = NOTES_SEED.map((n) => ({ ...n }));

export const orders: Order[] = [
  {
    id: "o-alice-1",
    ownerId: "u-alice",
    item: "ノートPCスタンド",
    amount: 3980,
  },
  {
    id: "o-bob-1",
    ownerId: "u-bob",
    item: "ワイヤレスマウス",
    amount: 2480,
  },
];

/** Mutable profiles for mass-assignment demos */
export const profiles = new Map<string, Profile>(
  users.map((u) => [
    u.id,
    {
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      role: u.role,
      bio: `${u.displayName} の自己紹介（デモ）`,
    },
  ]),
);

/** Simple in-memory rate-limit buckets keyed by IP/client */
export const rateBuckets = new Map<
  string,
  { count: number; resetAt: number }
>();

/** CSRF demo sessions keyed by session cookie value */
export const csrfSessions = new Map<string, CsrfSession>();

export function findUserByUsername(username: string): User | undefined {
  return users.find((u) => u.username === username);
}

export function findUserById(id: string): User | undefined {
  return users.find((u) => u.id === id);
}

export function findNoteById(id: string): Note | undefined {
  return notes.find((n) => n.id === id);
}

export function findOrderById(id: string): Order | undefined {
  return orders.find((o) => o.id === id);
}

export function resetProfiles(): void {
  for (const u of users) {
    profiles.set(u.id, {
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      role: "user",
      bio: `${u.displayName} の自己紹介（デモ）`,
    });
  }
}

export function resetNotes(): void {
  notes = NOTES_SEED.map((n) => ({ ...n }));
}

export function updateNote(
  id: string,
  patch: { title?: string; body?: string },
): Note | undefined {
  const note = findNoteById(id);
  if (!note) return undefined;
  if (typeof patch.title === "string") note.title = patch.title;
  if (typeof patch.body === "string") note.body = patch.body;
  return note;
}

export function deleteNote(id: string): boolean {
  const idx = notes.findIndex((n) => n.id === id);
  if (idx < 0) return false;
  notes.splice(idx, 1);
  return true;
}

export function createCsrfSession(user: User): CsrfSession {
  const sessionId = `sess-${user.username}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const csrfToken = `csrf-${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
  const session: CsrfSession = {
    sessionId,
    userId: user.id,
    username: user.username,
    csrfToken,
    balance: 10_000,
  };
  csrfSessions.set(sessionId, session);
  return session;
}

export function findCsrfSession(sessionId: string | undefined): CsrfSession | undefined {
  if (!sessionId) return undefined;
  return csrfSessions.get(sessionId);
}
