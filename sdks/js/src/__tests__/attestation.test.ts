/**
 * Tests for the client-side attestation verifier. Builds mock attestation
 * documents matching the postq-enclave Phase 1 wire format and exercises
 * the happy path + a couple of tamper cases.
 */

import crypto from "node:crypto";
import { verifyAttestationDoc } from "../attestation";
import type { AttestationPolicy } from "../index";

interface Doc {
  docB64: string;
  rootPubB64: string;
  imageHash: string;
  payloadSha256?: string;
  sigSha256?: string;
}

function buildMockDoc(opts: {
  imageHash?: string;
  issuedAt?: string;
  claims?: Record<string, unknown>;
  payloadSha256?: string;
  sigSha256?: string;
  vendor?: string;
} = {}): Doc {
  const imageHash = opts.imageHash ?? "a".repeat(64);
  const issuedAt = opts.issuedAt ?? new Date().toISOString();
  const claims = opts.claims ?? {
    kind: "sign",
    counter: 1,
    payloadSha256: opts.payloadSha256 ?? "p".repeat(64),
    sigSha256: opts.sigSha256 ?? "s".repeat(64),
  };
  const header = {
    alg: "EdDSA",
    typ: "PostQ-Attestation-Mock",
  };
  const payload = {
    vendor: opts.vendor ?? "mock",
    imageHash,
    claims,
    nonce: Buffer.alloc(16, 7).toString("base64"),
    issuedAt,
    rootKeyId: "test-root",
  };
  const b64u = (b: Buffer) =>
    b
      .toString("base64")
      .replace(/=+$/, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  const headerB64u = b64u(Buffer.from(JSON.stringify(header), "utf8"));
  const payloadB64u = b64u(Buffer.from(JSON.stringify(payload), "utf8"));
  const signingInput = Buffer.from(`${headerB64u}.${payloadB64u}`, "utf8");

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const sig = crypto.sign(null, signingInput, privateKey);
  // strip SPKI to raw 32 bytes
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const rootRaw = spki.subarray(spki.length - 32);

  const jws = `${headerB64u}.${payloadB64u}.${b64u(sig)}`;
  return {
    docB64: Buffer.from(jws, "utf8").toString("base64"),
    rootPubB64: rootRaw.toString("base64"),
    imageHash,
    payloadSha256: opts.payloadSha256,
    sigSha256: opts.sigSha256,
  };
}

function policy(
  rootPubB64: string,
  imageHash: string,
  overrides: Partial<AttestationPolicy> = {},
): Pick<AttestationPolicy, "vendor" | "matchRules" | "maxDocAgeSeconds"> {
  return {
    vendor: "mock",
    matchRules: {
      rootPublicKeyB64: rootPubB64,
      allowedImageHashes: [imageHash],
    },
    maxDocAgeSeconds: 300,
    ...overrides,
  };
}

describe("verifyAttestationDoc — mock vendor", () => {
  it("accepts a well-formed doc under a matching policy", async () => {
    const d = buildMockDoc();
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(d.rootPubB64, d.imageHash),
    });
    expect(res.ok).toBe(true);
    expect(res.vendor).toBe("mock");
    expect(res.imageHash).toBe(d.imageHash);
    expect(res.counter).toBe(1);
  });

  it("rejects when the policy vendor doesn't match the input vendor", async () => {
    const d = buildMockDoc();
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: {
        ...policy(d.rootPubB64, d.imageHash),
        vendor: "aws-nitro-enclave",
      },
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/policy vendor/);
  });

  it("rejects when the doc imageHash isn't in the allow-list", async () => {
    const d = buildMockDoc({ imageHash: "b".repeat(64) });
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(d.rootPubB64, "c".repeat(64)),
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/not in allowlist/);
  });

  it("rejects when the signature was made by a different root key", async () => {
    const d = buildMockDoc();
    // generate an unrelated root
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const wrongRoot = spki.subarray(spki.length - 32).toString("base64");
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(wrongRoot, d.imageHash),
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/does not verify/);
  });

  it("rejects when sigSha256 binding doesn't match", async () => {
    const d = buildMockDoc({ sigSha256: "s".repeat(64) });
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(d.rootPubB64, d.imageHash),
      expectedSigSha256: "z".repeat(64),
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/sigSha256 mismatch/);
  });

  it("rejects stale docs when enforceFreshness is on (default)", async () => {
    const oldIso = new Date(Date.now() - 600_000).toISOString();
    const d = buildMockDoc({ issuedAt: oldIso });
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(d.rootPubB64, d.imageHash),
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/doc age/);
  });

  it("accepts stale docs when enforceFreshness=false (audit-replay)", async () => {
    const oldIso = new Date(Date.now() - 600_000).toISOString();
    const d = buildMockDoc({ issuedAt: oldIso });
    const res = await verifyAttestationDoc({
      docB64: d.docB64,
      vendor: "mock",
      policy: policy(d.rootPubB64, d.imageHash),
      enforceFreshness: false,
    });
    expect(res.ok).toBe(true);
  });
});

describe("verifyAttestationDoc — unsupported vendors", () => {
  it.each([
    "aws-nitro-enclave",
    "azure-confidential-vm",
    "gcp-confidential-space",
  ] as const)("returns ok=false for %s", async (vendor) => {
    const res = await verifyAttestationDoc({
      docB64: Buffer.from("anything").toString("base64"),
      vendor,
      policy: { vendor, matchRules: {}, maxDocAgeSeconds: 300 },
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/not implemented/);
  });
});
