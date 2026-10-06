/**
 * Test helpers.
 *
 * Small on purpose. A test-helper framework would be a dependency of the test
 * suite for the sake of two functions, and the api's supply-chain argument
 * extends to what runs in CI.
 */

import { deriveCsrfToken } from "../src/session.js";

/** parseSetCookies returns a response's Set-Cookie header values. */
export function parseSetCookies(response: { headers: Record<string, unknown> }): string[] {
  const raw = response.headers["set-cookie"];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw.map(String) : [String(raw)];
}

/** derive is a local alias, so tests read as prose. */
export function derive(csrfKey: string, sessionId: string): string {
  return deriveCsrfToken(csrfKey, sessionId);
}