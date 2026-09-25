/**
 * Minimal OpenAPI 3.0 document covering a subset of this lab's API.
 * Used by GET /api/openapi.json and POST /api/safe/openapi-check.
 */

export const openApiDocument = {
  openapi: "3.0.3",
  info: {
    title: "API Security Lab (subset)",
    version: "2.0.0",
    description:
      "Educational OpenAPI subset for cross-checking request shape vs declared paths/fields. Local lab only.",
  },
  servers: [{ url: "http://localhost:8787" }],
  paths: {
    "/api/health": {
      get: {
        summary: "Health check",
        responses: {
          "200": {
            description: "OK",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    ok: { type: "boolean" },
                    service: { type: "string" },
                    port: { type: "integer" },
                  },
                },
              },
            },
          },
        },
      },
    },
    "/api/safe/auth/login": {
      post: {
        summary: "Issue JWT",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["username", "password"],
                properties: {
                  username: { type: "string" },
                  password: { type: "string" },
                  expiresIn: { type: "integer" },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": { description: "Token issued" },
          "401": { description: "Invalid credentials" },
        },
      },
    },
    "/api/safe/auth/me": {
      get: {
        summary: "Current user via JWT",
        security: [{ bearerAuth: [] }],
        responses: {
          "200": { description: "Authenticated user" },
          "401": { description: "Missing/invalid token" },
        },
      },
    },
    "/api/safe/notes/{id}": {
      get: {
        summary: "Get own note (ownership check)",
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          "200": { description: "Note" },
          "403": { description: "Not owner" },
          "404": { description: "Not found" },
        },
      },
      put: {
        summary: "Update own note",
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  title: { type: "string" },
                  body: { type: "string" },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": { description: "Updated" },
          "403": { description: "Not owner" },
        },
      },
      delete: {
        summary: "Delete own note",
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          "200": { description: "Deleted" },
          "403": { description: "Not owner" },
        },
      },
    },
    "/api/safe/profile": {
      post: {
        summary: "Update profile (allowlist)",
        security: [{ bearerAuth: [] }],
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  displayName: { type: "string" },
                  bio: { type: "string" },
                },
                additionalProperties: false,
              },
            },
          },
        },
        responses: {
          "200": { description: "Updated" },
        },
      },
    },
    "/api/safe/rate-limited": {
      get: {
        summary: "Rate-limited ping",
        responses: {
          "200": { description: "OK" },
          "429": { description: "Too many requests" },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
      },
    },
  },
} as const;

export type OpenApiCheckRequest = {
  method?: string;
  path?: string;
  body?: unknown;
};

export type OpenApiCheckResult = {
  mode: "safe";
  method: string;
  path: string;
  pathDeclared: boolean;
  methodDeclared: boolean;
  undeclaredPath: boolean;
  undeclaredFields: string[];
  declaredFields: string[];
  extraNotes: string[];
  message: string;
};

function normalizePath(raw: string): string {
  let p = raw.trim();
  if (!p.startsWith("/")) p = `/${p}`;
  // strip query
  p = p.split("?")[0] ?? p;
  return p;
}

/** Match /api/safe/notes/n-bob-1 against /api/safe/notes/{id} */
function matchPath(
  template: string,
  actual: string,
): boolean {
  const tParts = template.split("/");
  const aParts = actual.split("/");
  if (tParts.length !== aParts.length) return false;
  for (let i = 0; i < tParts.length; i++) {
    const t = tParts[i]!;
    const a = aParts[i]!;
    if (t.startsWith("{") && t.endsWith("}")) continue;
    if (t !== a) return false;
  }
  return true;
}

function schemaPropertyNames(schema: unknown): string[] {
  if (!schema || typeof schema !== "object") return [];
  const s = schema as Record<string, unknown>;
  const props = s.properties;
  if (!props || typeof props !== "object") return [];
  return Object.keys(props as Record<string, unknown>);
}

export function checkAgainstOpenApi(
  input: OpenApiCheckRequest,
): OpenApiCheckResult {
  const method = (input.method ?? "GET").toUpperCase();
  const path = normalizePath(input.path ?? "/");
  const paths = openApiDocument.paths as Record<
    string,
    Record<string, unknown>
  >;

  let matchedTemplate: string | null = null;
  for (const template of Object.keys(paths)) {
    if (matchPath(template, path)) {
      matchedTemplate = template;
      break;
    }
  }

  const undeclaredPath = matchedTemplate === null;
  const pathOps = matchedTemplate ? paths[matchedTemplate] : undefined;
  const opKey = method.toLowerCase();
  const operation =
    pathOps && typeof pathOps === "object"
      ? (pathOps[opKey] as Record<string, unknown> | undefined)
      : undefined;
  const methodDeclared = Boolean(operation);

  let declaredFields: string[] = [];
  const undeclaredFields: string[] = [];
  const extraNotes: string[] = [];

  if (operation) {
    const rb = operation.requestBody as
      | {
          content?: {
            "application/json"?: { schema?: unknown };
          };
        }
      | undefined;
    const schema = rb?.content?.["application/json"]?.schema;
    declaredFields = schemaPropertyNames(schema);

    if (input.body !== undefined && input.body !== null) {
      if (typeof input.body !== "object" || Array.isArray(input.body)) {
        extraNotes.push("body はオブジェクトを想定しています");
      } else {
        const keys = Object.keys(input.body as Record<string, unknown>);
        if (declaredFields.length === 0 && keys.length > 0) {
          extraNotes.push(
            "このオペレーションに requestBody スキーマが無いのに body が送られています",
          );
          undeclaredFields.push(...keys);
        } else {
          for (const k of keys) {
            if (!declaredFields.includes(k)) undeclaredFields.push(k);
          }
        }
        const allowsAdditional =
          schema &&
          typeof schema === "object" &&
          (schema as { additionalProperties?: unknown }).additionalProperties !==
            false;
        if (
          undeclaredFields.length > 0 &&
          schema &&
          typeof schema === "object" &&
          (schema as { additionalProperties?: unknown }).additionalProperties ===
            false
        ) {
          extraNotes.push(
            "spec は additionalProperties: false — 未宣言フィールドは拒否されるべき",
          );
        } else if (undeclaredFields.length > 0 && allowsAdditional) {
          extraNotes.push(
            "spec が additionalProperties を明示禁止していない場合でも、実装側で allowlist することを推奨",
          );
        }
      }
    }
  } else if (!undeclaredPath) {
    extraNotes.push(
      `パスは宣言されているが method ${method} はこのパスに無い`,
    );
  }

  let message: string;
  if (undeclaredPath) {
    message = `パス ${path} は OpenAPI に宣言されていません（シャドー API / ドキュメント漏れの疑い）`;
  } else if (!methodDeclared) {
    message = `${method} ${path} は OpenAPI に宣言されていません`;
  } else if (undeclaredFields.length > 0) {
    message = `宣言パスだが未宣言フィールドあり: ${undeclaredFields.join(", ")}`;
  } else {
    message = `${method} ${path} は OpenAPI に宣言済みで、body フィールドも整合しています`;
  }

  return {
    mode: "safe",
    method,
    path,
    pathDeclared: !undeclaredPath,
    methodDeclared,
    undeclaredPath,
    undeclaredFields,
    declaredFields,
    extraNotes,
    message,
  };
}

/** Rough YAML dump for /api/openapi.yaml (enough for lab reading) */
export function openApiAsYaml(): string {
  // Hand-written subset YAML kept in sync with openApiDocument paths
  return `# API Security Lab — OpenAPI 3.0 subset (v2)
# Educational only. Full JSON: GET /api/openapi.json
openapi: 3.0.3
info:
  title: API Security Lab (subset)
  version: "2.0.0"
  description: Educational OpenAPI subset for cross-checking requests.
servers:
  - url: http://localhost:8787
paths:
  /api/health:
    get:
      summary: Health check
  /api/safe/auth/login:
    post:
      summary: Issue JWT
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [username, password]
              additionalProperties: false
              properties:
                username: { type: string }
                password: { type: string }
                expiresIn: { type: integer }
  /api/safe/auth/me:
    get:
      summary: Current user via JWT
  /api/safe/notes/{id}:
    get:
      summary: Get own note
    put:
      summary: Update own note
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                title: { type: string }
                body: { type: string }
    delete:
      summary: Delete own note
  /api/safe/profile:
    post:
      summary: Update profile (allowlist)
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                displayName: { type: string }
                bio: { type: string }
  /api/safe/rate-limited:
    get:
      summary: Rate-limited ping
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
`;
}
