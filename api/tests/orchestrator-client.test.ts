import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONTAINER_VERB_TIMEOUT_MS,
  OrchestratorClient,
  computeSignature,
  signingString,
  type OrchestratorResult,
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

  // The both-ends pin for `boundSessions`, the other half of which is
  // `orchestrator/internal/pool`'s `TestStatsMarshalsBoundSessionsUnderItsJSONKey`.
  //
  // The two components share no code and this field crosses an HTTP boundary, so
  // the name is a contract that only a literal on both sides can hold. If either
  // side renames it, the sweep's orphan branch silently stops finding anything —
  // and it would stop finding it *quietly*, because every other test would still
  // pass with the field simply absent.
  //
  // The key's existence is asserted before its contents are read: a content
  // assertion against an absent field is vacuously true, which is the failure mode
  // this whole test exists to prevent.
  it("reads boundSessions off the literal key the orchestrator marshals", async () => {
    const body = JSON.stringify({
      size: 2,
      byState: { idle: 1, bound: 1 },
      runnerTtlSeconds: 300,
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-1": "3f2504e0-4f89-11d3-9a0c-0305e82c3301" },
    });
    // Asserted on the wire, before the client is involved at all.
    expect("boundSessions" in (JSON.parse(body) as Record<string, unknown>)).toBe(true);

    const c = client(stubFetch(200, body));
    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.boundSessions).toEqual({
      "slot-1": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    });
  });

  // The other direction of the rolling deploy: an orchestrator predating the field
  // omits it entirely (`omitempty`), and that must read as "this orchestrator does
  // not say" rather than as an empty pool with nothing bound.
  it("reads an orchestrator that omits boundSessions as not saying, not as empty", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({ size: 2, byState: { idle: 2 }, runnerTtlSeconds: 300, slotIds: ["slot-1"] }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.boundSessions).toBeUndefined();
  });
});

/**
 * The per-verb budget.
 *
 * ## Why this file's worth an assertion per verb
 *
 * The client budget was 15 s for everything. The orchestrator's own worst case for a
 * claim is ~57 s — a 10 s SIGTERM grace to stop the idle runner, ~2 s to create and
 * start its replacement, and a 45 s healthcheck wait — so the api was aborting
 * legitimate claims *mid-provision*. Far-side, the in-flight Docker calls died with
 * the request context, and two containers were left running and invisible to the
 * pool. The user saw a failed login, twice.
 *
 * The number is a property of the far side's work, so it cannot be re-derived here.
 * What this pins is that each verb carries the budget the constant names, and that
 * the four container verbs are not silently sharing the read budget again.
 */
describe("per-verb timeout budgets", () => {
  const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

  const client = (fetchImpl: typeof fetch) =>
    new OrchestratorClient({
      baseUrl: "http://orchestrator:9100",
      secret: SECRET,
      fetchImpl,
      now: () => new Date(Number(TS)),
    });

  /**
   * A fetch that never resolves on its own and settles only when its signal aborts —
   * the shape of a call against an orchestrator that has stopped answering, which is
   * the only situation the timeout exists for.
   *
   * `seen.at` records the fake-clock time of the abort, because *when* the client
   * gives up is the assertion; a promise that merely settles eventually would not
   * distinguish a 15 s budget from a 75 s one.
   */
  function wedgedFetch(seen: { at: number | null }): typeof fetch {
    return ((_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          seen.at = Date.now();
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      })) as typeof fetch;
  }

  /**
   * Drives one wedged call across the fake clock and reports how much of it elapsed
   * before the client aborted.
   *
   * `observeMs` is deliberately *less* than the budget for the "does not give up"
   * assertion: a client that had already given up would show `settled: true` here,
   * which is the regression being pinned rather than a timing fluke.
   */
  async function wedge(
    invoke: (c: OrchestratorClient) => Promise<OrchestratorResult<unknown>>,
    observeMs: number,
  ): Promise<{
    abortedAfterMs: number | null;
    settled: boolean;
    result?: OrchestratorResult<unknown>;
  }> {
    const seen = { at: null as number | null };
    const c = client(wedgedFetch(seen));
    const startedAt = Date.now();
    const pending = invoke(c);
    let settled = false;
    void pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );

    await vi.advanceTimersByTimeAsync(observeMs);

    const abortedAfterMs = seen.at === null ? null : seen.at - startedAt;
    if (!settled) return { abortedAfterMs, settled: false };
    return { abortedAfterMs, settled: true, result: await pending };
  }

  /** The four verbs whose server-side work is a container lifecycle. */
  const containerVerbs: Array<[string, (c: OrchestratorClient) => Promise<OrchestratorResult<unknown>>]> =
    [
      ["claim", (c) => c.claim(GUID, new Date(Number(TS)))],
      ["release", (c) => c.release("slot-1")],
      ["recycle", (c) => c.recycle("slot-1", "runner ttl")],
      ["remove", (c) => c.remove("slot-1")],
    ];

  /** The reads, which stay on the 15 s default. */
  const readVerbs: Array<[string, (c: OrchestratorClient) => Promise<OrchestratorResult<unknown>>]> =
    [
      ["stat", (c) => c.stat(ARTIFACT_ID)],
      ["stats", (c) => c.stats()],
    ];

  afterEach(() => {
    vi.useRealTimers();
  });

  for (const [verb, invoke] of containerVerbs) {
    it(`does not abort ${verb} at the old 15s mark`, async () => {
      vi.useFakeTimers();

      const { settled, abortedAfterMs } = await wedge(invoke, 15_000);

      expect(abortedAfterMs).toBeNull();
      expect(settled).toBe(false);
    });

    it(`aborts ${verb} inside the container-verb budget, and says so`, async () => {
      vi.useFakeTimers();

      const { settled, abortedAfterMs, result } = await wedge(
        invoke,
        CONTAINER_VERB_TIMEOUT_MS + 1,
      );

      expect(settled).toBe(true);
      expect(abortedAfterMs).toBe(CONTAINER_VERB_TIMEOUT_MS);
      // The cause carries the number, because this is the string an operator reads to
      // tell a slow orchestrator from a budget that was too small for the work. It
      // was the field `sweep.ts` dropped on the floor, and losing it is why the 15 s
      // was unrecoverable from the api's own log.
      expect(result).toEqual({
        ok: false,
        error: { kind: "unreachable", cause: `timed out after ${CONTAINER_VERB_TIMEOUT_MS}ms` },
      });
    });
  }

  for (const [verb, invoke] of readVerbs) {
    it(`still gives up on ${verb} at 15s`, async () => {
      vi.useFakeTimers();

      const { settled, abortedAfterMs, result } = await wedge(invoke, 15_001);

      expect(settled).toBe(true);
      expect(abortedAfterMs).toBe(15_000);
      // Reads are fast, and a long budget on a wedged read would hold a request open
      // for nothing — so widening the container verbs must not have widened these.
      expect(result).toEqual({
        ok: false,
        error: { kind: "unreachable", cause: "timed out after 15000ms" },
      });
    });
  }

  // The derivation itself, asserted rather than trusted: the budget has to clear the
  // orchestrator's worst case (10 s stop grace + ~2 s create/start + 45 s ready) or
  // the api is back to aborting legitimate claims mid-provision. The number in the
  // orchestrator's own comment is 57 s; this pins it from the api's side.
  it("clears the orchestrator's worst case for a claim", () => {
    const stopGraceMs = 10_000;
    const createAndStartMs = 2_000;
    const runnerReadyTimeoutMs = 45_000;

    expect(CONTAINER_VERB_TIMEOUT_MS).toBeGreaterThan(
      stopGraceMs + createAndStartMs + runnerReadyTimeoutMs,
    );
  });
});