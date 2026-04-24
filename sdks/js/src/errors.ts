/** Base error for all SDK failures. Catch this to catch them all. */
export class PostQError extends Error {
  /** HTTP status code (0 for network errors, undefined for config errors). */
  readonly status?: number;
  /** Original API error code, if the server returned one. */
  readonly code?: string;

  constructor(message: string, opts: { status?: number; code?: string } = {}) {
    super(message);
    this.name = "PostQError";
    this.status = opts.status;
    this.code = opts.code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when constructor input is missing or invalid. */
export class PostQConfigError extends PostQError {
  constructor(message: string) {
    super(message);
    this.name = "PostQConfigError";
  }
}

/** 401 — bad, missing, revoked, or expired API key. */
export class PostQAuthError extends PostQError {
  constructor(message: string, code?: string) {
    super(message, { status: 401, code });
    this.name = "PostQAuthError";
  }
}

/** 404 — resource not found. */
export class PostQNotFoundError extends PostQError {
  constructor(message: string, code?: string) {
    super(message, { status: 404, code });
    this.name = "PostQNotFoundError";
  }
}

/** 429 — rate limit exceeded. */
export class PostQRateLimitError extends PostQError {
  constructor(message: string, code?: string) {
    super(message, { status: 429, code });
    this.name = "PostQRateLimitError";
  }
}

/** 5xx — server error. */
export class PostQServerError extends PostQError {
  constructor(message: string, status: number, code?: string) {
    super(message, { status, code });
    this.name = "PostQServerError";
  }
}

/** Network failure — DNS, connection refused, timeout. */
export class PostQNetworkError extends PostQError {
  constructor(message: string) {
    super(message, { status: 0 });
    this.name = "PostQNetworkError";
  }
}
