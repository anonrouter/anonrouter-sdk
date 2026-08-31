// Generate an image and synthesize speech over the two-origin ticket exchange.
//
// BILLABLE. This performs real generations against real providers, so it is not
// run by CI and it is not run without a key. Everything before the generation is
// free: if you only want to confirm the routes exist and fail closed, run
//
//   ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai \
//   ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai npx vitest run test/live-media.test.ts
//
// which probes both origins with no credential and no spend.
//
// What the example demonstrates, and the reason these methods exist: ONE call
// here is TWO HTTP requests to two different hosts. The control origin sees your
// API key and the content-free shape of the work; the confidential origin sees
// the prompt and only a single-use ticket. No configuration of the official
// OpenAI SDK can do that -- it has one base URL and one credential.

import "./_env.js";
import { writeFile } from "node:fs/promises";
import { createClient, MediaError } from "../src/index.js";

const apiKey = process.env.ANONROUTER_API_KEY;
if (!apiKey) {
  console.error("Set ANONROUTER_API_KEY (or put it in js/confidential/.env).");
  console.error("This example performs REAL, BILLABLE generations.");
  process.exit(2);
}

const IMAGE_MODEL = process.env.ANONROUTER_IMAGE_MODEL ?? "venice/flux-dev";
const SPEECH_MODEL = process.env.ANONROUTER_SPEECH_MODEL ?? "venice/tts-kokoro";
const VOICE = process.env.ANONROUTER_SPEECH_VOICE;

// The production origins are the defaults, so this is the whole configuration.
// Override with ANONROUTER_BASE_URL / ANONROUTER_CONTROL_URL to point at another
// deployment; the two must be different hosts or media is refused.
const client = createClient({
  apiKey,
  ...(process.env.ANONROUTER_BASE_URL ? { inferenceBaseUrl: process.env.ANONROUTER_BASE_URL } : {}),
  ...(process.env.ANONROUTER_CONTROL_URL ? { controlBaseUrl: process.env.ANONROUTER_CONTROL_URL } : {})
});

async function generateImage(): Promise<void> {
  console.log(`\nimage   model=${IMAGE_MODEL}`);
  const result = await client.images.generate({
    model: IMAGE_MODEL,
    prompt: "a lighthouse in a storm, painted in oils",
    size: "1024x1024"
  });
  const image = result.data[0];
  await writeFile("anonrouter-image.png", image.bytes);
  console.log(`        wrote anonrouter-image.png (${image.bytes.length} bytes, ${image.mime_type})`);
  console.log(`        routed to ${result.selected_model ?? "(model not reported)"}`);
  if (result.provider_content_violation) {
    // Delivered on a 200 with a header rather than as an error: the moderation
    // verdict is about your prompt and stays in the content plane.
    console.log("        provider flagged a content violation");
  }
}

async function synthesizeSpeech(): Promise<void> {
  console.log(`\nspeech  model=${SPEECH_MODEL}`);
  const result = await client.audio.speech.create({
    model: SPEECH_MODEL,
    input: "The quick brown fox jumps over the lazy dog.",
    ...(VOICE ? { voice: VOICE } : {})
  });
  await writeFile("anonrouter-speech.mp3", result.audio);
  console.log(`        wrote anonrouter-speech.mp3 (${result.audio.length} bytes, ${result.content_type})`);
  console.log(`        routed to ${result.selected_model ?? "(model not reported)"}`);
}

try {
  await generateImage();
  await synthesizeSpeech();
  console.log("\nBoth generations completed. The control origin never saw either prompt.");
} catch (error) {
  if (error instanceof MediaError) {
    // The code is what to branch on. `provider_failed` is the only one that may
    // correspond to work a provider actually attempted and charged for.
    console.error(`\nFAILED  code=${error.code}`);
    console.error(`        ${error.message}`);
    console.error(`        origin=${error.diagnostics.origin}${error.diagnostics.path}`);
    if (error.diagnostics.request_id) console.error(`        request_id=${error.diagnostics.request_id}`);
    // Headers are printed with every credential value already redacted.
    console.error(`        headers=${JSON.stringify(error.diagnostics.headers)}`);
    process.exit(1);
  }
  throw error;
}
