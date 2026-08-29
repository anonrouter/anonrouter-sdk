// gzip/gunzip via the standard Compression Streams API (available in browsers and
// in Node >= 18). Used only by the Chutes ML-KEM transport: its request body is
// gzip(JSON) and the response is gzip'd inside the encrypted envelope. No Node
// zlib, no polyfill. gunzip is capped to defend against a decompression bomb in a
// hostile or altered response.

import { asBufferSource, concatBytes } from "./bytes.js";
import { ConfidentialError } from "./errors.js";

async function pump(
  stream: ReadableStream<Uint8Array>,
  maxOutputBytes: number,
  code: "encrypt_failed" | "decrypt_failed"
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > maxOutputBytes) {
          await reader.cancel().catch(() => undefined);
          throw new ConfidentialError(code, "The encrypted payload exceeded the size limit.");
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return concatBytes(...chunks);
}

/** gzip a byte array. Output is bounded (input is our own bounded JSON). */
export async function gzip(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  // Attach catches so an early reader.cancel() (size cap) cannot surface these as
  // unhandled rejections when the writable side is torn down.
  writer.write(asBufferSource(data)).catch(() => undefined);
  writer.close().catch(() => undefined);
  // Compressed output is never larger than input + a small header, cap generously.
  return pump(cs.readable, data.byteLength + 4096, "encrypt_failed");
}

/** gunzip a byte array, refusing to expand beyond `maxOutputBytes`. */
export async function gunzip(data: Uint8Array, maxOutputBytes: number): Promise<Uint8Array> {
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(asBufferSource(data)).catch(() => undefined);
  writer.close().catch(() => undefined);
  return pump(ds.readable, maxOutputBytes, "decrypt_failed");
}
