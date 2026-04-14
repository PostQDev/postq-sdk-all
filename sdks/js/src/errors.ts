import type { PostQApiError } from "./types";

/** Error thrown when the PostQ API returns a non-2xx response. */
export class PostQError extends Error {
  /** HTTP status code returned by the API. */
  readonly statusCode: number;
  /** Machine-readable error code from the API, if available. */
  readonly code: string | undefined;

  constructor(message: string, statusCode: number, code?: string) {
    super(message);
    this.name = "PostQError";
    this.statusCode = statusCode;
    this.code = code;
    // Maintain proper prototype chain in TypeScript subclasses.
    Object.setPrototypeOf(this, PostQError.prototype);
  }

  /** Create a PostQError from an API error payload and HTTP status code. */
  static fromApiError(err: PostQApiError, statusCode: number): PostQError {
    return new PostQError(err.message, statusCode, err.code);
  }
}

/** Error thrown when required configuration is missing or invalid. */
export class PostQConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PostQConfigError";
    Object.setPrototypeOf(this, PostQConfigError.prototype);
  }
}
