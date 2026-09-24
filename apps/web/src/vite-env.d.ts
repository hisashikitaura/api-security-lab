/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_WRONG_API_SECRET?: string;
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
