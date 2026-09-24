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

export const DEMO_API_KEY = "lab-demo-key";
/** Server-only secret — never expose via VITE_ env */
export const SERVER_SECRET = "server-only-lab-secret-do-not-put-in-vite";
export const JWT_SECRET = new TextEncoder().encode(
  "lab-jwt-signing-secret-demo-only",
);
export const RATE_LIMIT_MAX = 5;
export const RATE_LIMIT_WINDOW_MS = 10_000;

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

export const notes: Note[] = [
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
