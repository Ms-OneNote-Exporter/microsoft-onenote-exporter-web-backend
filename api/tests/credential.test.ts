import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  MAX_CREDENTIAL_BYTES,
  auditFields,
  capStream,
  checkFraming,
  contentTypeIsAcceptable,
  countOnly,
} from "../src/credential.js";

/**
 * PLAN-v3 §3.1, §3.3; PLAN-v2 §4.2. T-A5 and the log-grep assertions behind
 * T-A2 are exercised by the absence of any buffer-returning function in this
 * module: there is nothing here that can hold a credential.
 */

/** A readable over the given bytes. */
function source(bytes: Uint8Array): Readable {
  return Readable.from([Buffer.from(bytes)]);
}

/** Drain a stream and return its bytes. */
async function drain(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk as Buffer));
  }
  return Buffer.concat(chunks);
}

describe("checkFraming", () => {
  it("accepts a length within the cap", () => {
    expect(checkFraming("0")).toEqual({ ok: true, declaredLength: 0 });
    expect(checkFraming("11")).toEqual({ ok: true, declaredLength: 11 });
    expect(checkFraming("4096")).toEqual({ ok: true, declaredLength: 4096 });
  });

  it("refuses an oversized declared length before forwarding anything", () => {
    // The point of checking first: the runner must never see a prefix of a body
    // that is too large.
    const result = checkFraming("4097");
    expect(result).toEqual({ ok: false, refusal: "content-length-too-large" });
    expect(checkFraming(String(1024 * 1024))).toEqual({
      ok: false,
      refusal: "content-length-too-large",
    });
  });

  it("refuses a missing Content-Length rather than assuming one", () => {
    // Assuming would mean the cap could only be enforced mid-stream, after the
    // runner had already acted on the first bytes.
    expect(checkFraming(undefined)).toEqual({ ok: false, refusal: "no-content-length" });
    expect(checkFraming("")).toEqual({ ok: false, refusal: "no-content-length" });
  });

  it("refuses a malformed or negative length", () => {
    for (const bad of ["abc", "-1", "1.5", "NaN", "0x10", "1e3"]) {
      expect(checkFraming(bad)).toEqual({ ok: false, refusal: "no-content-length" });
    }
  });
});

describe("capStream", () => {
  it("passes a small body through byte for byte", async () => {
    const bytes = Buffer.from("hunter2", "utf8");
    expect(await drain(capStream(source(bytes)))).toEqual(bytes);
  });

  it("passes a body at exactly the cap through intact", async () => {
    const bytes = Buffer.alloc(MAX_CREDENTIAL_BYTES, 0x41);
    expect(await drain(capStream(source(bytes)))).toHaveLength(MAX_CREDENTIAL_BYTES);
  });

  it("cuts off one byte past the cap and errors", async () => {
    const bytes = Buffer.alloc(MAX_CREDENTIAL_BYTES + 1, 0x41);
    const stream = capStream(source(bytes));
    await expect(drain(stream)).rejects.toThrow(/exceeded the cap/);
  });

  it("never emits more than the cap, even from a large source", async () => {
    // A caller who understates Content-Length and sends a large body must not be
    // able to make this process buffer it.
    const bytes = Buffer.alloc(4 * 1024 * 1024, 0x42);
    const stream = capStream(source(bytes));

    let received = 0;
    await expect(
      (async () => {
        for await (const chunk of stream) {
          received += (chunk as Buffer).length;
        }
      })(),
    ).rejects.toThrow(/exceeded the cap/);

    expect(received).toBeLessThanOrEqual(MAX_CREDENTIAL_BYTES);
  });

  it("honours a custom limit", async () => {
    const bytes = Buffer.from("0123456789", "utf8");
    await expect(drain(capStream(source(bytes), 4))).rejects.toThrow(/exceeded the cap/);
  });

  it("destroys the source on overflow so the connection does not stay open", async () => {
    // Leaving the caller's connection open would hold the handler open
    // indefinitely, which is a worse failure than a refused credential.
    const bytes = Buffer.alloc(MAX_CREDENTIAL_BYTES + 1, 0x41);
    const src = source(bytes);
    let destroyed = false;
    src.on("close", () => {
      destroyed = true;
    });

    await expect(drain(capStream(src))).rejects.toThrow();
    // The close event is emitted asynchronously; one turn is enough.
    await new Promise((resolve) => setImmediate(resolve));
    expect(destroyed).toBe(true);
  });

  it("ends cleanly on an empty body", async () => {
    expect(await drain(capStream(source(new Uint8Array(0))))).toHaveLength(0);
  });

  it("does not mangle bytes that are not valid UTF-8", async () => {
    // A password can contain anything after encoding; a credential path that
    // round-tripped through a string would corrupt it.
    const bytes = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc3]);
    expect(await drain(capStream(source(bytes)))).toEqual(bytes);
  });
});

describe("countOnly", () => {
  it("counts without retaining", () => {
    const sink = countOnly();
    sink.write(Buffer.alloc(10));
    sink.write(Buffer.alloc(5));
    expect(sink.bytes()).toBe(15);
  });

  it("exposes no way to read what it counted", () => {
    // The absence of a getter for the content is the property.
    expect(Object.keys(countOnly())).toEqual(["write", "bytes"]);
  });
});

describe("contentTypeIsAcceptable", () => {
  // PLAN-v3 §3.3 layer 3: this route deliberately does not pin a content type.
  it("accepts text/plain, which is what the frontend sends", () => {
    expect(contentTypeIsAcceptable("text/plain")).toBe(true);
    expect(contentTypeIsAcceptable("text/plain; charset=utf-8")).toBe(true);
    expect(contentTypeIsAcceptable("TEXT/PLAIN")).toBe(true);
  });

  it("accepts anything non-multipart, because it is never parsed", () => {
    for (const type of ["application/json", "application/x-www-form-urlencoded", "text/html"]) {
      expect(contentTypeIsAcceptable(type)).toBe(true);
    }
  });

  it("accepts a missing content type", () => {
    expect(contentTypeIsAcceptable(undefined)).toBe(true);
    expect(contentTypeIsAcceptable("")).toBe(true);
  });

  it("rejects multipart, which would want a parser enabled globally", () => {
    expect(contentTypeIsAcceptable("multipart/form-data; boundary=x")).toBe(false);
    expect(contentTypeIsAcceptable("MULTIPART/MIXED")).toBe(false);
  });
});

describe("auditFields", () => {
  it("logs only shape, never content", () => {
    const fields = auditFields({
      contentLength: "11",
      contentType: "text/plain",
      origin: "https://app.example.com",
    });
    expect(fields).toEqual({
      contentLength: "11",
      contentType: "text/plain",
      origin: "https://app.example.com",
      credentialPresent: true,
      credentialLogged: false,
    });
  });

  it("carries no cookie or authorization value", () => {
    // A cookie value on this route is a session secret, so it must not appear in
    // an audit line. Asserted by checking no key could hold one.
    const fields = auditFields({ contentLength: "11", contentType: undefined, origin: undefined });
    for (const key of Object.keys(fields)) {
      expect(key.toLowerCase()).not.toContain("cookie");
      expect(key.toLowerCase()).not.toContain("authorization");
    }
  });

  it("represents absent headers as null rather than undefined, so the field exists", () => {
    const fields = auditFields({ contentLength: undefined, contentType: undefined, origin: undefined });
    expect(fields.contentLength).toBeNull();
    expect(fields.contentType).toBeNull();
    expect(fields.origin).toBeNull();
  });
});