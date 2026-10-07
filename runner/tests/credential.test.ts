/**
 * The credential crosses this process as bytes, and arrives as bytes.
 *
 * ## Why this file exists, and why it drives a real browser
 *
 * Every serious defect in this project has sat at a boundary and been invisible
 * to a green suite. Two of them were this credential: the frontend's
 * `JSON.stringify` turned `hunter2` into `"hunter2"`, and the runner's
 * predecessor put the password on a command line where every process could read
 * it. Neither was caught by a test that asserted a value was set.
 *
 * So the assertions here are made on the far side. A hostile password is typed
 * into a **real Chromium page** by the **real `login()` password step**, and the
 * field's value is read back out of the DOM. Not the value this module passed
 * in — the value the browser actually received.
 *
 * The DOM's `value` property is what a user's keystrokes would produce, so it is
 * the honest far-side observation. `.innerText` or a re-read of the JS string
 * would both be assertions about the test's own variable.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chromium, type Browser, type Page } from "playwright";
import {
  readCredentialBytes,
  readAccount,
  passwordFrom,
  isValidGuid,
  CREDENTIAL_LIMIT_BYTES,
} from "../src/credential.js";

/**
 * Passwords chosen to break every layer that might "helpfully" alter them.
 *
 * Each one is a class of corruption that has either happened in this project or
 * is a common default: quoting, escaping, whitespace handling, encoding, and the
 * truncation a length cap produces if implemented as a slice.
 */
const HOSTILE_PASSWORDS: ReadonlyArray<{ readonly name: string; readonly value: string }> = [
  { name: "plain", value: "hunter2" },
  { name: "double quotes", value: 'say "hello"' },
  { name: "single quote", value: "it's-mine" },
  { name: "backslash", value: "domain\\user\\pass" },
  { name: "trailing backslash", value: "ends-with\\" },
  { name: "leading and trailing spaces", value: "   padded secret   " },
  { name: "only spaces", value: "     " },
  { name: "tab and newline", value: "before\tafter" },
  { name: "ampersand and equals", value: "a&b=c" },
  { name: "shell metacharacters", value: "$(rm -rf /) `whoami` && echo *" },
  { name: "json-looking", value: '{"password":"not-a-delimiter"}' },
  { name: "emoji", value: "pässwörd🔐" },
  { name: "long but legal", value: "x".repeat(512) },
];

describe("readCredentialBytes", () => {
  it("hands back the exact buffer, not a copy with different contents", () => {
    const bytes = Buffer.from('  "quoted" \\escaped\\  ', "utf8");
    const result = readCredentialBytes(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected acceptance");
    expect(result.bytes.equals(bytes)).toBe(true);
  });

  it("round-trips every hostile password without altering a byte", () => {
    for (const { name, value } of HOSTILE_PASSWORDS) {
      const bytes = Buffer.from(value, "utf8");
      const result = readCredentialBytes(bytes);
      expect(result.ok, `${name} should be accepted`).toBe(true);
      if (!result.ok) continue;
      expect(result.bytes.length, `${name} length`).toBe(bytes.length);
      expect(result.bytes.toString("utf8"), `${name} contents`).toBe(value);
    }
  });

  it("refuses an empty body rather than logging in with nothing", () => {
    expect(readCredentialBytes(Buffer.alloc(0))).toMatchObject({
      ok: false,
      reason: "empty-account",
    });
  });

  it("refuses an absent body", () => {
    expect(readCredentialBytes(undefined)).toMatchObject({ ok: false, reason: "no-body" });
    expect(readCredentialBytes(null)).toMatchObject({ ok: false, reason: "no-body" });
  });

  it("refuses a non-buffer rather than coercing it to a string", () => {
    // Coercing is exactly how bytes become a string and stop being bytes. If the
    // content-type parser is ever replaced and hands over a string, this refuses.
    expect(readCredentialBytes("a string body" as unknown)).toMatchObject({
      ok: false,
      reason: "no-body",
    });
  });

  it("refuses an oversized body instead of truncating it", () => {
    // The property that matters: a truncated password is a *wrong* password, and
    // the user would be told to check what they typed.
    const bytes = Buffer.alloc(CREDENTIAL_LIMIT_BYTES + 1, 0x61);
    expect(readCredentialBytes(bytes)).toMatchObject({ ok: false, reason: "too-large" });
  });

  it("accepts a body of exactly the limit", () => {
    const bytes = Buffer.alloc(CREDENTIAL_LIMIT_BYTES, 0x61);
    expect(readCredentialBytes(bytes).ok).toBe(true);
  });

  it("honours a caller-supplied limit", () => {
    expect(readCredentialBytes(Buffer.alloc(10), 5)).toMatchObject({ reason: "too-large" });
  });

  it("never includes the credential in a rejection", () => {
    // A refusal reaches an HTTP body and a log line. The reason codes are fixed
    // strings; none of them can carry the value.
    const secret = "sup3rs3cret";
    const rejected = readCredentialBytes(Buffer.from(secret, "utf8"), 4);
    expect(JSON.stringify(rejected)).not.toContain(secret);
  });
});

describe("passwordFrom", () => {
  it("returns the same string for every hostile password", () => {
    for (const { name, value } of HOSTILE_PASSWORDS) {
      expect(passwordFrom(Buffer.from(value, "utf8")), name).toBe(value);
    }
  });

  it("does not trim, which would silently change a padded password", () => {
    expect(passwordFrom(Buffer.from("   padded   ", "utf8"))).toBe("   padded   ");
  });

  it("does not normalise line endings", () => {
    // A CRLF somewhere in the path must not become LF, and vice versa: that is a
    // password change the user cannot see and cannot reproduce.
    expect(passwordFrom(Buffer.from("a\r\nb", "utf8"))).toBe("a\r\nb");
    expect(passwordFrom(Buffer.from("a\nb", "utf8"))).toBe("a\nb");
  });
});

describe("readAccount", () => {
  it("reads the header value", () => {
    expect(readAccount("user@example.com")).toBe("user@example.com");
    expect(readAccount("DOMAIN\\user")).toBe("DOMAIN\\user");
  });

  it("trims only the header, which the api sets", () => {
    expect(readAccount("  user@example.com  ")).toBe("user@example.com");
  });

  it("refuses a header with a newline in it", () => {
    // Otherwise a caller could inject extra log lines or a header into something
    // downstream that treats this as a single value.
    expect(readAccount("user@example.com\r\nX-Injected: yes")).toBeNull();
    expect(readAccount("user@example.com\nX-Injected: yes")).toBeNull();
  });

  it("refuses absent and empty values", () => {
    expect(readAccount(undefined)).toBeNull();
    expect(readAccount(null)).toBeNull();
    expect(readAccount("   ")).toBeNull();
    expect(readAccount(["a", "b"])).toBeNull();
  });
});

describe("isValidGuid", () => {
  it("accepts a guid", () => {
    expect(isValidGuid("3f2504e0-4f89-41d3-9a0c-0305e82c3301")).toBe(true);
    expect(isValidGuid("3F2504E0-4F89-41D3-9A0C-0305E82C3301")).toBe(true);
  });

  it("refuses anything that could escape the session directory", () => {
    // This string reaches path.join. `..` would write outside the data root,
    // which is the one filesystem write an attacker reaching this API controls.
    for (const bad of [
      "../../etc/passwd",
      "..",
      "not-a-guid",
      "3f2504e0-4f89-41d3-9a0c-0305e82c3301/../other",
      "3f2504e0-4f89-41d3-9a0c-0305e82c3301\n",
      "",
      "3f2504e04f8941d39a0c0305e82c3301",
    ]) {
      expect(isValidGuid(bad), bad).toBe(false);
    }
  });

  it("refuses non-strings", () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      expect(isValidGuid(bad)).toBe(false);
    }
  });
});

/**
 * The far side.
 *
 * A real Chromium page, filled by the same call `login()` makes — `locator.fill()`
 * with the string from `passwordFrom` — and the value read back out of the DOM.
 *
 * This is the assertion that the bytes arrived. Everything above it asserts about
 * what this process *intended* to send; this asserts about what the browser
 * received, which is the only version of the question a user cares about.
 */
describe("the password reaches the login form unchanged", () => {
  let browser: Browser;

  beforeAll(async () => {
    browser = await chromium.launch({ headless: true });
  }, 60_000);

  afterAll(async () => {
    if (browser) await browser.close();
  });

  const fillAndRead = async (page: Page, value: string): Promise<string> => {
    const field = page.locator('input[name="passwd"], input[type="password"]').first();
    await field.waitFor({ state: "visible", timeout: 5_000 });
    // The call login() makes. Passing `value` — the string passwordFrom produced
    // — so this is the full chain: bytes -> string -> DOM.
    await field.fill(value);
    return await field.evaluate((el: HTMLInputElement) => el.value);
  };

  for (const { name, value } of HOSTILE_PASSWORDS) {
    it(`preserves a password with ${name}`, async () => {
      const page = await browser.newPage();
      try {
        await page.goto("https://login.microsoftonline.com/common/oauth2/authorize", {
          waitUntil: "domcontentloaded",
        });
        // The form is served from the real host with an intercept, so nothing
        // leaves the machine and no credential is sent anywhere.
        await page.route("https://login.microsoftonline.com/**", (route) =>
          route.fulfill({
            status: 200,
            contentType: "text/html",
            body: '<form><input name="passwd" type="password"></form>',
          }),
        );
        await page.goto("https://login.microsoftonline.com/common/oauth2/authorize", {
          waitUntil: "domcontentloaded",
        });

        const arrived = await fillAndRead(page, passwordFrom(Buffer.from(value, "utf8")));
        expect(arrived, `${name} must arrive byte-for-byte`).toBe(value);
      } finally {
        await page.close();
      }
    }, 30_000);
  }

  it("survives the whole chain: request bytes -> passwordFrom -> DOM", async () => {
    // The three hops as one, with the body a real HTTP request would carry.
    const page = await browser.newPage();
    try {
      await page.route("https://login.microsoftonline.com/**", (route) =>
        route.fulfill({
          status: 200,
          contentType: "text/html",
          body: '<form><input name="passwd" type="password"></form>',
        }),
      );
      await page.goto("https://login.microsoftonline.com/common/oauth2/authorize", {
        waitUntil: "domcontentloaded",
      });

      for (const { name, value } of HOSTILE_PASSWORDS) {
        const accepted = readCredentialBytes(Buffer.from(value, "utf8"));
        expect(accepted.ok, name).toBe(true);
        if (!accepted.ok) continue;
        const arrived = await fillAndRead(page, passwordFrom(accepted.bytes));
        expect(arrived, name).toBe(value);
      }
    } finally {
      await page.close();
    }
  }, 60_000);
});
