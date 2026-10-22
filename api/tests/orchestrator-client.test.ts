import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONTAINER_VERB_TIMEOUT_MS,
  OrchestratorClient,
  computeSignature,
  signingString,
  type OrchestratorResult,
} from "../src/orchestrator-client.js";
// The reader this file's `byState` bodies are pinned *for*. Imported here rather than
// re-derived as a local `!== undefined` so the literal below is checked against the
// answer the sweeper will actually read — two copies of "what an absent key means" in one
// repository is how the two drift.
import { poolBindsNobody, poolClaimable, poolIdleCount } from "../src/sweep.js";

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
  method?: string;
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
      seen.method = init?.method;
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

  // The ninth verb. `finalize` publishes an artifact into
  // `<artifactId>/vault.zip` on a volume this process cannot see (PLAN-v3
  // §4.3/§4.4), so without a way to say "and now take it away" an erased session's
  // vault stayed on the disk while the api told the user everything was deleted.
  //
  // The signed path is the assertion, not the method: a verb that reached the
  // orchestrator unsigned would be an open endpoint, and it is the one deletion
  // verb on this surface.
  it("sends a signed POST /delete-artifact carrying only the artifact id", async () => {
    const seen: Seen = {};
    const c = client(stubFetch(200, JSON.stringify({ deleted: true }), seen));

    const result = await c.deleteArtifact(ARTIFACT_ID);

    expect(result.ok).toBe(true);
    expect(seen.method).toBe("POST");
    expect(seen.url).toBe("http://orchestrator:9100/delete-artifact");
    // One field, and it is an identifier: this is the verb that removes a
    // directory, so anything else on the schema would be a way to name a path.
    expect(JSON.parse(seen.body ?? "{}")).toEqual({ artifactId: ARTIFACT_ID });
    expect(seen.headers?.["x-msout-sig"]).toBe(
      computeSignature(SECRET, TS, "POST", "/delete-artifact", Buffer.from(seen.body ?? "", "utf8")),
    );
  });

  // Idempotent by contract, and the client has to be able to say so: erase is
  // best-effort and retried, and "already gone" is the outcome it wanted.
  it("reports success for an artifact that was already gone", async () => {
    const c = client(stubFetch(200, JSON.stringify({ deleted: true })));
    await expect(c.deleteArtifact(ARTIFACT_ID)).resolves.toMatchObject({ ok: true });
  });

  // A refusal is typed, not thrown, and not flattened to `ok: false`: the erase
  // machine's step is the only record that a published vault survived, so it has to
  // be able to say *how* it failed.
  it("maps a server error to a typed unexpected, not a throw", async () => {
    const c = client(stubFetch(500, JSON.stringify({ error: "internal error" })));
    const result = await c.deleteArtifact(ARTIFACT_ID);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.kind).toBe("unexpected");
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

  // The both-ends pin for the per-slot budget, whose other half is
  // `orchestrator/internal/pool`'s `TestStatsMarshalsSlotBudgetUnderItsJSONKeys`.
  //
  // Same argument as `boundSessions` above: two components, no shared code, a name
  // that is only a contract. If either side renames a key the claim's floor check
  // silently stops firing — and it would stop *quietly*, because every other test
  // would pass with the field simply absent.
  //
  // The keys' existence is asserted on the wire before the client is involved, since
  // a content assertion against an absent field is vacuously true.
  it("reads slotAgeSec and slotRemainingSec off the literal keys the orchestrator marshals", async () => {
    const body = JSON.stringify({
      size: 2,
      byState: { idle: 2 },
      runnerTtlSeconds: 300,
      slotIds: ["slot-1", "slot-2"],
      slotAgeSec: { "slot-1": 240, "slot-2": 12 },
      slotRemainingSec: { "slot-1": 60, "slot-2": 288 },
    });
    for (const key of ["slotAgeSec", "slotRemainingSec"]) {
      expect(key in (JSON.parse(body) as Record<string, unknown>)).toBe(true);
    }

    const c = client(stubFetch(200, body));
    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Seconds, keyed by slot id, carried through untouched: the client does no
    // arithmetic on a number only the orchestrator can compute.
    expect(result.value.slotAgeSec).toEqual({ "slot-1": 240, "slot-2": 12 });
    expect(result.value.slotRemainingSec).toEqual({ "slot-1": 60, "slot-2": 288 });
  });

  // The other direction of the rolling deploy, and the half that has to keep working:
  // an orchestrator predating the field omits it (`omitempty`), and that must read as
  // "does not say" rather than as a pool whose slots have nothing left — which the
  // claim's floor check would refuse every login over.
  it("reads an orchestrator that omits the slot budget as not saying, not as empty", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({ size: 2, byState: { idle: 2 }, runnerTtlSeconds: 300, slotIds: ["slot-1"] }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.slotRemainingSec).toBeUndefined();
    expect(result.value.slotAgeSec).toBeUndefined();
  });

  // A slot holding no container is absent from both maps, not present with a zero. The
  // difference is the whole reason the caller can distinguish "no age" from "no
  // budget", and it is what `omitempty` plus a zero `CreatedAt` produce on the far
  // side.
  it("carries a partial slot budget through without filling in the missing slots", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({
          size: 2,
          byState: { idle: 1, starting: 1 },
          runnerTtlSeconds: 300,
          slotIds: ["slot-1", "slot-2"],
          slotRemainingSec: { "slot-1": 0 },
        }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // `slot-1` is reported as spent, and `slot-2` — no container yet — is absent.
    // A `Record` filled in with zeros would make both indistinguishable, and a claim
    // would refuse a slot that has not been created.
    expect(result.value.slotRemainingSec).toEqual({ "slot-1": 0 });
    expect("slot-2" in (result.value.slotRemainingSec ?? {})).toBe(false);
  });

  // The both-ends pin for `byState`, the other half of which is
  // `orchestrator/internal/pool`'s `TestStatsByStateKeysAreKnownStateNames`.
  //
  // Same argument as `boundSessions` above — two components, no shared code, a name that
  // is only a contract — but load-bearing in a way the others are not. `byState` is how
  // the sweeper reaches a strand on an **all-idle pool**, which is the ordinary state of
  // a pool nobody is using and the one shape `boundSessions` cannot report at all
  // (`omitempty` over a nil map). A silent drift here would not degrade: it would restore
  // D6 exactly, and every other test would still pass.
  //
  // **The literal below is the body captured from the deployed host** on 2026-10-18, not
  // a hand-written approximation — that is the whole point of pinning this one, since the
  // property under test is an *absence* and an approximation would carry whatever keys
  // the author happened to type. Read off it: no `bound` key, and no `boundSessions`.
  it("reads byState off a body with no bound key, and calls that nothing being bound", async () => {
    const c = client(
      stubFetch(
        200,
        '{"size":2,"byState":{"idle":2},"runnerTtlSeconds":300,"slotIds":["slot-20","slot-21"],"slotAgeSec":{"slot-20":1428,"slot-21":408},"slotRemainingSec":{"slot-20":0,"slot-21":0}}',
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // **The key is absent, not `0`** — asserted as a key set rather than as a value,
    // because `expect(result.value.byState).toEqual({idle: 2})` would also pass for a
    // client that filled the gap in, and filling it in is the bug this guards.
    expect(result.value.byState).toEqual({ idle: 2 });
    expect("bound" in result.value.byState).toBe(false);
    // And the absence is what the sweeper reads. `byState` is only a repair if "no
    // `bound` key" is answerable as "nothing is bound by anyone".
    expect(poolBindsNobody(result.value.byState)).toBe(true);
  });

  // The other half of the same reading, and the case that keeps the absence from being
  // over-read: one bound slot is enough to stand the branch down, whatever the field
  // above says about it.
  it("calls a pool with a bound slot nothing-bound-is-not", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({
          size: 2,
          byState: { idle: 1, bound: 1 },
          runnerTtlSeconds: 300,
          slotIds: ["slot-1", "slot-2"],
        }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(poolBindsNobody(result.value.byState)).toBe(false);
  });

  // A body with **no** `byState` at all. Unlike the three fields above, `ByState` has
  // never carried `omitempty`, so this is not a rolling deploy — it is a malformed
  // response — and the only safe reading of it is "cannot ask". A `?? 0` default here
  // would say "nothing is bound" and dispose of every live export on the pool.
  it("reads a body with no byState as cannot-ask, not as nothing being bound", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({ size: 2, runnerTtlSeconds: 300, slotIds: ["slot-1", "slot-2"] }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(poolBindsNobody(result.value.byState)).toBeUndefined();
  });

  // The both-ends pin for `claimableSlotIds`, the other half of which is
  // `orchestrator/internal/pool`'s `Stats` method which populates it.
  //
  // The two components share no code and this field crosses an HTTP boundary, so
  // the name is a contract that only a literal on both sides can hold. If either
  // side renames it, the api's draw will not exclude non-claimable slots, and
  // logins will fail on a slot the orchestrator refuses.
  it("reads claimableSlotIds off the literal key the orchestrator marshals", async () => {
    const body = JSON.stringify({
      size: 3,
      byState: { idle: 1, bound: 2 },
      runnerTtlSeconds: 300,
      slotIds: ["slot-1", "slot-2", "slot-3"],
      claimableSlotIds: ["slot-1"],
    });
    // Asserted on the wire, before the client is involved at all.
    expect("claimableSlotIds" in (JSON.parse(body) as Record<string, unknown>)).toBe(true);

    const c = client(stubFetch(200, body));
    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.claimableSlotIds).toEqual(["slot-1"]);
  });

  // The rolling deploy backwards: an orchestrator predating the field omits it
  // entirely (`omitempty`), and that must read as "this orchestrator does not say"
  // rather than as an empty set.
  it("reads an orchestrator that omits claimableSlotIds as not saying, not as empty", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({ size: 2, byState: { idle: 2 }, runnerTtlSeconds: 300, slotIds: ["slot-1"] }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.claimableSlotIds).toBeUndefined();
  });

  // A pool where no slots are claimable should still omit the key rather than
  // sending an empty list, to match the real orchestrator's marshaling behavior.
  it("reads a pool with no claimable slots as omitting the key", async () => {
    const c = client(
      stubFetch(
        200,
        JSON.stringify({ size: 2, byState: { bound: 2 }, runnerTtlSeconds: 300, slotIds: ["slot-1", "slot-2"] }),
      ),
    );

    const result = await c.stats();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The key should be absent, not an empty array.
    expect("claimableSlotIds" in result.value).toBe(false);
  });
});

describe("poolClaimable vocabulary refusal", () => {
  // T-9: poolClaimable refuses an unfamiliar byState vocabulary.
  it("returns undefined for an unknown state name", () => {
    const result = poolClaimable({ "frob": 2 }, undefined);
    expect(result).toBeUndefined();
  });

  it("returns undefined when byState is undefined", () => {
    const result = poolClaimable(undefined, undefined);
    expect(result).toBeUndefined();
  });

  it("returns the claimable set when the vocabulary is known", () => {
    const result = poolClaimable({ idle: 1, bound: 1 }, ["slot-1"]);
    expect(result).toEqual(new Set(["slot-1"]));
  });

  it("returns an empty set when no slots are claimable", () => {
    const result = poolClaimable({ bound: 2 }, undefined);
    expect(result).toEqual(new Set());
  });

  it("returns undefined when some are claimable but ids are missing", () => {
    const result = poolClaimable({ idle: 1 }, undefined);
    expect(result).toBeUndefined();
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