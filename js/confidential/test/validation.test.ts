import { describe, expect, it } from "vitest";
import { ConfidentialError } from "../src/errors.js";
import { validateE2eeMessages, validateE2eeRequest } from "../src/transport/validation.js";

const base = { model: "z-ai/glm-5.2", upstreamModel: "z-ai/glm-5.2", maxOutputTokens: 256 };

describe("e2ee request validation", () => {
  it("accepts a user/system text request", () => {
    const request = validateE2eeRequest({
      ...base,
      messages: [
        { role: "system", content: "You are terse." },
        { role: "user", content: "Hello" }
      ]
    });
    expect(request.messages).toHaveLength(2);
  });

  it("accepts assistant history (multi-turn)", () => {
    const request = validateE2eeRequest({
      ...base,
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "hello" },
        { role: "user", content: "continue" }
      ]
    });
    expect(request.messages).toHaveLength(3);
    expect(request.messages[1].role).toBe("assistant");
  });

  it("rejects tool messages", () => {
    const call = () => validateE2eeMessages([{ role: "user", content: "hi" }, { role: "tool", content: "prior" }]);
    expect(call).toThrowError(ConfidentialError);
    try { call(); } catch (error) { expect((error as ConfidentialError).code).toBe("unsupported_request"); }
  });

  it("rejects multi-modal (non-string) content", () => {
    expect(() => validateE2eeMessages([{ role: "user", content: [{ type: "image_url" }] }]))
      .toThrowError(/text content only/i);
  });

  it("rejects an unknown role", () => {
    expect(() => validateE2eeMessages([{ role: "developer", content: "x" }]))
      .toThrowError(/user, system, and assistant/i);
  });

  it("requires at least one user message", () => {
    expect(() => validateE2eeMessages([{ role: "system", content: "only system" }]))
      .toThrowError(/needs a user message/i);
  });
});
