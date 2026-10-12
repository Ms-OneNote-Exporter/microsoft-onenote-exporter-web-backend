/**
 * Type declarations for the three `@msout` packages.
 *
 * ## Why these are hand-written
 *
 * The packages are plain CommonJS JavaScript with no `.d.ts` files, so
 * `tsc --noEmit` refuses to import them. An untyped import compiles fine and
 * types everything as `any` — which means `login()` accepting a typo like
 * `authFil` would be caught by nothing, and this is the one process that holds a
 * credential.
 *
 * Declared here rather than in the packages because the packages are consumed
 * **unmodified**; `runner/README.md` is explicit that they are not forked, and a
 * type declaration is not a fork but an edit is. If a package's signature
 * changes, the mismatch shows up as a typecheck failure here, which is the
 * correct direction: the runner is the thing that has to keep working.
 *
 * ## What is asserted, and what is not
 *
 * Only what the runner uses, and only what is genuinely part of the contract.
 * Optional fields are marked optional rather than declared required, because a
 * type that lies about a field's presence produces a false green at exactly the
 * moment the field is renamed.
 */

declare module "@msout/microsoft-webauth" {
  /** One event from `login()`. Mirrors `LOGIN_EVENT_TYPES`. */
  export interface LoginEvent {
    readonly type: string;
    readonly [key: string]: unknown;
  }

  /**
   * Automated sign-in.
   *
   * Resolves `true` only when the session authenticated **and** the auth state
   * was written and read back. Never throws — an unrecognised failure resolves
   * `false` like any other.
   */
  export function login(options: {
    email: string;
    /** Bytes as a string. Never trimmed, never normalised. */
    password: string;
    authFile: string;
    targetUrl?: string;
    onEvent?: (event: LoginEvent) => void;
    notheadless?: boolean;
    dodump?: boolean;
    screenshot?: boolean;
  }): Promise<boolean>;

  /** Verifies a saved session. `authenticated` is false when it cannot confirm. */
  export function verifyAuth(options: {
    targetUrl?: string;
    authFilePath: string;
  }): Promise<{ authenticated: boolean; reason: string; detail: string }>;

  /** The frozen reason union. A caller asserts its mapping table against this. */
  export const LOGIN_REASONS: readonly string[];
  /** The frozen event-name union. */
  export const LOGIN_EVENT_TYPES: readonly string[];
  /** The frozen challenge-kind union. */
  export const CHALLENGE_KINDS: readonly string[];
}

declare module "@msout/microsoft-onenote-list-notebooks" {
  export interface NotebookEntry {
    readonly name: string;
    readonly url: string;
    readonly id?: string;
  }

  /**
   * One event from `listNotebooks()`. Mirrors `LIST_EVENT_TYPES`, which is
   * **not** on the package's main entry — it is exported by the
   * `@msout/microsoft-onenote-list-notebooks/observer` subpath, alongside
   * `createListingObserver`. `tests/observer-contract.test.ts` reads it from
   * there.
   *
   * One name, and it is a literal rather than `string`: the package freezes the
   * list, so a second name would be a package change this declaration would have
   * to absorb silently. `ListEvent` and the runner's own `RunnerEvent` member are
   * the same three fields, which is why a line can be published without being
   * rebuilt.
   */
  export interface ListEvent {
    readonly type: "listing-log";
    /** Already undecorated by the package: no timestamp, no colour escapes. */
    readonly line: string;
    readonly level: string;
  }

  /**
   * Lists notebooks from a saved session.
   *
   * **Resolves a bare array — `NotebookEntry[]`, not `{notebooks}`.** The
   * declaration previously said `{notebooks: NotebookEntry[]}`, which was simply
   * false, and the false part was load-bearing: `result.notebooks` on an array is
   * `undefined`, so `?? []` produced an empty list and the runner published an
   * empty notebook list on every run. See the route in `src/index.ts`.
   *
   * `keepOpen` is **not read by the package** — there is no such option in
   * `listNotebooks()` — so the runner's `keepOpen: false` is inert and the
   * browser is closed by the package itself when the listing returns. Kept in the
   * declaration because the call site still passes it: the honest correction is to
   * stop describing it as behaviour, not to leave the typecheck failing on a
   * line nobody has agreed to delete.
   *
   * `onEvent` is optional and its absence is the package's default: a listing
   * without one behaves exactly as it did before 0.0.8, which is what its CLI
   * relies on. So a runner on 0.0.7 and a runner on 0.0.8 both list; only the
   * lines differ.
   */
  export function listNotebooks(options: {
    authFile: string;
    /** Inert. See above: no such option in the package. */
    keepOpen?: boolean;
    notheadless?: boolean;
    onEvent?: (event: ListEvent) => void;
  }): Promise<NotebookEntry[]>;
}

declare module "@msout/microsoft-onenote-export-notebook" {
  /** Counts-so-far. Never a fraction — mid-run the totals are unknown. */
  export interface ExportProgress {
    readonly pages: number;
    readonly sections: number;
    readonly assets: number;
  }

  export interface ExportEvent {
    readonly type: string;
    readonly [key: string]: unknown;
  }

  /**
   * Exports a notebook to a directory.
   *
   * Rejects on failure, deliberately, so a caller can tell a failed export from
   * an empty one. An abort resolves normally with the partial stats.
   */
  export function runExport(options: {
    authFile: string;
    exportDir: string;
    /** By URL, preferred over a name that could collide. */
    notebookLink?: string;
    notebook?: string;
    /** The caller's run id, echoed on every event. */
    id?: string;
    /** Stops between sections, keeps what was written, resolves. */
    signal?: AbortSignal;
    onEvent?: (event: ExportEvent) => void;
    nonInteractive?: boolean;
    nopassasked?: boolean;
    notheadless?: boolean;
    dodump?: boolean;
    screenshot?: boolean;
  }): Promise<Record<string, unknown>>;

  export const EXPORT_EVENT_TYPES: readonly string[];
  export const PARTIAL_REASONS: readonly string[];
}
