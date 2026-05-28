/**
 * Client-side attestation verification.
 *
 * `verifyAttestationDoc()` lets callers re-check an attestation doc returned
 * by `/v1/sign` without trusting the API's verdict — the security model is
 * "verify under a policy you pinned locally". Mirrors the verifier in
 * postq-site/apps/api/src/lib/vault/attestation-verifier.ts.
 *
 * Today only the `mock` vendor is implemented (matches postq-enclave Phase 1
 * wire format). Real vendors (Nitro / Azure CVM / GCP Confidential Space)
 * are reserved and will be added alongside their backend.
 */

import crypto from "node:crypto";
import type {
  AttestationVerifyInput,
  AttestationVerifyResult,
} from "./types";

export async function verifyAttestationDoc(
  input: AttestationVerifyInput,
): Promise<AttestationVerifyResult> {
  if (input.policy.vendor !== input.vendor) {
    return {
      ok: false,
      vendor: input.vendor,
      reason: `policy vendor ${input.policy.vendor} != doc vendor ${input.vendor}`,
    };
  }
  switch (input.vendor) {
    case "mock":
      return verifyMock(input);
    case "aws-nitro-enclave":
    case "azure-confidential-vm":
    case "gcp-confidential-space":
      return {
        ok: false,
        vendor: input.vendor,
        reason: `vendor ${input.vendor} not implemented in @postq/sdk yet`,
      };
  }
}

// ── mock vendor ──────────────────────────────────────────────────────────

interface MockMatchRules {
  allowedImageHashes?: string[];
  rootPublicKeyB64?: string;
}

async function verifyMock(
  input: AttestationVerifyInput,
): Promise<AttestationVerifyResult> {
  const rules = input.policy.matchRules as MockMatchRules;
  if (typeof rules.rootPublicKeyB64 !== "string") {
    return {
      ok: false,
      vendor: "mock",
      reason: "policy.matchRules.rootPublicKeyB64 missing",
    };
  }
  const rootPub = Buffer.from(rules.rootPublicKeyB64, "base64");
  if (rootPub.length !== 32) {
    return {
      ok: false,
      vendor: "mock",
      reason: "rootPublicKeyB64 is not a 32-byte ed25519 key",
    };
  }

  const docBytes = Buffer.from(input.docB64, "base64");
  const text = docBytes.toString("utf8");
  const parts = text.split(".");
  if (parts.length !== 3) {
    return {
      ok: false,
      vendor: "mock",
      reason: "mock doc not in 3-part JWS shape",
    };
  }
  const [headerB64u, payloadB64u, sigB64u] = parts;

  let header: { alg?: string; typ?: string };
  let payload: {
    vendor?: string;
    imageHash?: string;
    claims?: Record<string, unknown>;
    nonce?: string;
    issuedAt?: string;
    rootKeyId?: string;
  };
  try {
    header = JSON.parse(Buffer.from(headerB64u, "base64url").toString("utf8"));
    payload = JSON.parse(
      Buffer.from(payloadB64u, "base64url").toString("utf8"),
    );
  } catch (err) {
    return {
      ok: false,
      vendor: "mock",
      reason: `mock doc parse: ${(err as Error).message}`,
    };
  }
  if (header.alg !== "EdDSA" || header.typ !== "PostQ-Attestation-Mock") {
    return {
      ok: false,
      vendor: "mock",
      reason: `mock doc header mismatch: ${JSON.stringify(header)}`,
    };
  }

  // Verify ed25519 signature over "<headerB64u>.<payloadB64u>"
  const signingInput = Buffer.from(`${headerB64u}.${payloadB64u}`, "utf8");
  const sig = Buffer.from(sigB64u, "base64url");
  if (sig.length !== 64) {
    return { ok: false, vendor: "mock", reason: "mock sig length != 64 bytes" };
  }
  // node:crypto needs SPKI DER; build one from the raw 32-byte key.
  const spki = ed25519RawToSpki(rootPub);
  const keyObj = crypto.createPublicKey({
    key: spki,
    format: "der",
    type: "spki",
  });
  const sigOk = crypto.verify(null, signingInput, keyObj, sig);
  if (!sigOk) {
    return {
      ok: false,
      vendor: "mock",
      reason: "mock signature does not verify under pinned root",
    };
  }

  if (payload.vendor !== "mock") {
    return {
      ok: false,
      vendor: "mock",
      reason: `payload.vendor=${payload.vendor}, expected mock`,
    };
  }
  const imageHash =
    typeof payload.imageHash === "string" ? payload.imageHash : undefined;
  if (!imageHash) {
    return { ok: false, vendor: "mock", reason: "payload.imageHash missing" };
  }
  const allowed = Array.isArray(rules.allowedImageHashes)
    ? rules.allowedImageHashes
    : [];
  if (allowed.length > 0 && !allowed.includes(imageHash)) {
    return {
      ok: false,
      vendor: "mock",
      imageHash,
      reason: `imageHash ${imageHash.slice(0, 12)}… not in allowlist`,
    };
  }
  if (typeof payload.issuedAt !== "string") {
    return { ok: false, vendor: "mock", reason: "payload.issuedAt missing" };
  }
  const enforceFreshness = input.enforceFreshness !== false;
  if (enforceFreshness) {
    const issuedAtMs = Date.parse(payload.issuedAt);
    if (Number.isNaN(issuedAtMs)) {
      return {
        ok: false,
        vendor: "mock",
        reason: "payload.issuedAt unparseable",
      };
    }
    const ageSeconds = Math.abs(Date.now() - issuedAtMs) / 1000;
    if (ageSeconds > input.policy.maxDocAgeSeconds) {
      return {
        ok: false,
        vendor: "mock",
        imageHash,
        reason: `doc age ${Math.round(ageSeconds)}s > max ${input.policy.maxDocAgeSeconds}s`,
      };
    }
  }

  const claims = (payload.claims ?? {}) as Record<string, unknown>;
  let counter: number | undefined;
  if (claims.kind === "sign") {
    if (
      input.expectedSigSha256 &&
      claims.sigSha256 !== input.expectedSigSha256
    ) {
      return {
        ok: false,
        vendor: "mock",
        imageHash,
        reason: "claims.sigSha256 mismatch",
      };
    }
    if (
      input.expectedPayloadSha256 &&
      claims.payloadSha256 !== input.expectedPayloadSha256
    ) {
      return {
        ok: false,
        vendor: "mock",
        imageHash,
        reason: "claims.payloadSha256 mismatch",
      };
    }
    if (typeof claims.counter === "number") counter = claims.counter;
  }

  return { ok: true, vendor: "mock", imageHash, counter, claims };
}

/**
 * Convert a 32-byte raw ed25519 public key to SPKI DER so node:crypto can
 * import it. SPKI for Ed25519 = fixed 12-byte AlgorithmIdentifier prefix
 * (OID 1.3.101.112) + raw key as BIT STRING.
 */
function ed25519RawToSpki(raw: Buffer): Buffer {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return Buffer.concat([prefix, raw]);
}
