import { describe, expect, it } from "vitest";
import {
  OrchestratorClient,
  computeSignature,
  signingString,
} from "../src/orchestrator-client.js";

/**
 * These tests pin the signing scheme against literal vectors produced by the Go
 * implementation in `orchestrator/internal/auth`.
 *
 * Both sides assemble the signed string independently — one in Go, one in
 * TypeScript — because the two components share no code. That is the point of
 * the HTTP boundary, and it is also the risk: if either side's string drifts,
 * every internal call fails as a 401 with no useful diagnostic. A shared literal
 * vector is what turns that from a production incident into a failing test.
 *
 * Regenerate with:
 *   cd orchestrator && cat > internal/auth/vector_test.go <<'EOF'
 *   ... then go test -run TestEmitVector -v
 */

const SECRET = "shared-test-secret-0123456789abcdef";
const TS = "1700000000000";
/** 43 base64url characters — the artifact id shape both sides validate. */
const ARTIFACT_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BODY = JSON.stringify({
  sessionGuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
});

describe("signing scheme interop", () => {
  it("matches the Go signing string byte for byte", () => {
    // From orchestrator/internal/auth: signingString("1700000000000", "POST", "/claim", body)
    expect(signingString(TS, "POST", "/claim", Buffer.from(BODY, "utf8"))).toBe(
      "1700000000000\nPOST\n/claim\n05e32f8f8b03b05af0e899c5eb6dca50e3cfd3b278d93c7433cf2da518f08b28",
    );
  });

  it("matches the Go signature for the same input", () => {
    // From orchestrator/internal/auth: Signature(secret, ts, "POST", "/claim", body)
    expect(
      computeSignature(SECRET, TS, "POST", "/claim", Buffer.from(BODY, "utf8")),
    ).toBe("4OI9qa19KvT_tL3AxMLmVc5TgQyIZH-ZibruXGYMU8s");
  });

  it("uppercases the method so get/post cannot be confused", () => {
    expect(signingString(TS, "post", "/claim", Buffer.from(BODY, "utf8"))).toBe(
      signingString(TS, "POST", "/claim", Buffer.from(BODY, "utf8")),
    );
  });

  it("changes the signature when any single field changes", () => {
    const base = computeSignature(SECRET, TS, "POST", "/claim", Buffer.from(BODY, "utf8"));
    const variants = [
      computeSignature(SECRET, "1700000000001", "POST", "/claim", Buffer.from(BODY, "utf8")),
      computeSignature(SECRET, TS, "GET", "/claim", Buffer.from(BODY, "utf8")),
      computeSignature(SECRET, TS, "POST", "/release", Buffer.from(BODY, "utf8")),
      computeSignature(SECRET, TS, "POST", "/claim", Buffer.from(`${BODY} `, "utf8")),
      computeSignature("other-secret", TS, "POST", "/claim", Buffer.from(BODY, "utf8")),
    ];
    for (const v of variants) {
      expect(v).not.toBe(base);
    }
  });
});

/** A fetch stand-in that records the request and returns a canned response. */
interface Seen {
  headers?: Record<string, unknown>;
  body?: string;
  url?: string;
}

/**
 * `seen` is optional on purpose: when it is omitted the stub must still work,
 * because a test that only cares about the mapped result should not have to
 * allocate a recorder. An earlier version dereferenced it unconditionally, which
 * threw a TypeError inside the client and made every status-mapping test report
 * "unreachable" — a misleading failure caused by the harness, not the code.
 */
function stubFetch(status: number, body: string, seen?: Seen): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (seen) {
      seen.url = String(url);
      seen.headers = init?.headers as Record<string, unknown>;
      seen.body =
        typeof init?.body === "string"
          ? init.body
          : init?.body instanceof Uint8Array
            ? Buffer.from(init.body).toString("utf8")
            : undefined;
    }
    return new Response(body, { status });
  }) as typeof fetch;
}

describe("OrchestratorClient", () => {
  const client = (fetchImpl: typeof fetch) =>
    new OrchestratorClient({
      baseUrl: "http://orchestrator:9100",
      secret: SECRET,
      fetchImpl,
      now: () => new Date(Number(TS)),
    });

  it("sends both signature headers on every call", async () => {
    const seen: Seen = {};
    const c = client(stubFetch(200, JSON.stringify({ exists: true, size: 42 }), seen));

    await c.stat("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    expect(seen.headers?.["x-msout-ts"]).toBe(TS);
    expect(seen.headers?.["x-msout-sig"]).toBe(
      computeSignature(SECRET, TS, "POST", "/stat", Buffer.from(JSON.stringify({ artifactId: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }), "utf8")),
    );
  });

  it("signs the exact bytes it sends", async () => {
    const seen: Seen = {};
    const c = client(stubFetch(200, "{}", seen));

    await c.claim("3f2504e0-4f89-11d3-9a0c-0305e82c3301", new Date(Number(TS)));

    const sent = Buffer.from(seen.body ?? "", "utf8");
    const expected = computeSignature(SECRET, TS, "POST", "/claim", sent);
    expect(seen.headers?.["x-msout-sig"]).toBe(expected);
    // And content-length agrees, so the signature covers the whole body.
    expect(seen.headers?.["content-length"]).toBe(String(sent.length));
  });

  it("carries the partial bit to /finalize verbatim", async () => {
    // The orchestrator selects the `.partial.zip` name and writes the marker from
    // this field, and by design it **cannot verify it** — it never saw the walk.
    // A client that quietly sent `partial: false` for a truncated vault would
    // publish it unmarked and indistinguishable from a complete one, which is the
    // one thing PLAN-v3 §5 exists to prevent. So the assertion is on the bytes.
    const seen: Seen = {};
    const c = client(
      stubFetch(
        200,
        JSON.stringify({
          artifactId: ARTIFACT_ID,
          archiveName: "vault.partial.zip",
          bytes: 512,
          partial: true,
        }),
        seen,
      ),
    );

    const result = await c.finalize({
      artifactId: ARTIFACT_ID,
      sessionGuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      partial: true,
    });

    expect(JSON.parse(seen.body ?? "{}")).toEqual({
      artifactId: ARTIFACT_ID,
      sessionGuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      partial: true,
    });
    expect(result.ok).toBe(true);
  });

  it("sends /finalize to the verb the orchestrator registered", async () => {
    const seen: Seen = {};
    const c = client(stubFetch(200, "{}", seen));

    await c.finalize({
      artifactId: ARTIFACT_ID,
      sessionGuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      partial: false,
    });

    expect(seen.url).toBe("http://orchestrator:9100/finalize");
  });

  it("maps a 409 from /finalize to a conflict, not a transport failure", async () => {
    // 409 here means "nothing staged" — the runner wrote no archive. That is a
    // different fact from "could not reach the orchestrator", and the caller treats
    // it by recording an unpublishable export rather than by retrying.
    const c = client(stubFetch(409, JSON.stringify({ error: "nothing staged to finalise" })));

    const result = await c.finalize({
      artifactId: ARTIFACT_ID,
      sessionGuid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      partial: false,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("conflict");
  });

  it("maps pool exhaustion to a typed error, not a throw", async () => {
    const c = client(stubFetch(503, JSON.stringify({ error: "no idle slot" })));
    const result = await c.claim("3f2504e0-4f89-11d3-9a0c-0305e82c3301", new Date());

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("pool-exhausted");
  });

  it("maps 401 and 400 to unauthorized so a clock or secret problem is visible", async () => {
    for (const status of [400, 401]) {
      const c = client(stubFetch(status, JSON.stringify({ error: "signature mismatch" })));
      const result = await c.stats();
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.kind).toBe("unauthorized");
    }
  });

  it("maps 409 to a conflict", async () => {
    const c = client(stubFetch(409, JSON.stringify({ error: "unknown slot" })));
    const result = await c.release("slot-1");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("conflict");
  });

  it("reports an unreachable orchestrator rather than throwing", async () => {
    const c = client((async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch);
    const result = await c.stats();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("unreachable");
      if (result.error.kind === "unreachable") {
        expect(result.error.cause).toContain("ECONNREFUSED");
      }
    }
  });

  it("never sends a body on GET", async () => {
    const seen: Seen = {};
    const c = client(stubFetch(200, "{}", seen));
    await c.stats();
    expect(seen.body).toBeUndefined();
  });

  it("strips a trailing slash from the base url", async () => {
    const seen: Seen = {};
    const c = new OrchestratorClient({
      baseUrl: "http://orchestrator:9100/",
      secret: SECRET,
      fetchImpl: stubFetch(200, "{}", seen),
      now: () => new Date(Number(TS)),
    });
    await c.stats();
    expect(seen.url).toBe("http://orchestrator:9100/stats");
  });
});