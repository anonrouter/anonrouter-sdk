"""Generate an image and synthesize speech over the two-origin ticket exchange.

BILLABLE. This performs real generations against real providers, so it is not run
by CI and it is not run without a key. Everything before the generation is free:
if you only want to confirm the routes exist and fail closed, run

    ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.anonrouter.ai \\
    ANONROUTER_LIVE_PUBLIC_ORIGIN=https://control.anonrouter.ai pytest tests/test_live_media.py

which probes both origins with no credential and no spend.

What the example demonstrates, and the reason these methods exist: ONE call here
is TWO HTTP requests to two different hosts. The control origin sees your API key
and the content-free shape of the work; the confidential origin sees the prompt
and only a single-use ticket. No configuration of the official OpenAI SDK can do
that -- it has one base URL and one credential.

The JavaScript twin is ``js/confidential/examples/media.ts``; it prints the same
things in the same order.
"""

from __future__ import annotations

import os
import sys

from anonrouter_confidential import MediaError, create_client

IMAGE_MODEL = os.environ.get("ANONROUTER_IMAGE_MODEL", "alibaba/z-image-turbo")
SPEECH_MODEL = os.environ.get("ANONROUTER_SPEECH_MODEL", "venice/kokoro-text-to-speech")
VOICE = os.environ.get("ANONROUTER_SPEECH_VOICE")


def main() -> int:
    api_key = os.environ.get("ANONROUTER_API_KEY")
    if not api_key:
        print("Set ANONROUTER_API_KEY.", file=sys.stderr)
        print("This example performs REAL, BILLABLE generations.", file=sys.stderr)
        return 2

    # The production origins are the defaults, so this is the whole
    # configuration. Override with ANONROUTER_BASE_URL / ANONROUTER_CONTROL_URL
    # to point at another deployment; the two must be different hosts or media is
    # refused.
    client = create_client(
        api_key=api_key,
        inference_base_url=os.environ.get("ANONROUTER_BASE_URL"),
        control_base_url=os.environ.get("ANONROUTER_CONTROL_URL"),
    )

    try:
        print(f"\nimage   model={IMAGE_MODEL}")
        image = client.images.generate(
            model=IMAGE_MODEL,
            prompt="a lighthouse in a storm, painted in oils",
            size="1024x1024",
        )
        first = image.data[0]
        with open("anonrouter-image.png", "wb") as handle:
            handle.write(first.data)
        print(
            f"        wrote anonrouter-image.png ({len(first.data)} bytes, {first.mime_type})"
        )
        print(f"        routed to {image.selected_model or '(model not reported)'}")
        if image.provider_content_violation:
            # Delivered on a 200 with a header rather than as an error: the
            # moderation verdict is about your prompt and stays in the content
            # plane.
            print("        provider flagged a content violation")

        print(f"\nspeech  model={SPEECH_MODEL}")
        speech = client.audio.speech.create(
            model=SPEECH_MODEL,
            input="The quick brown fox jumps over the lazy dog.",
            voice=VOICE,
        )
        written = speech.write_to("anonrouter-speech.mp3")
        print(
            f"        wrote anonrouter-speech.mp3 ({written} bytes, {speech.content_type})"
        )
        print(f"        routed to {speech.selected_model or '(model not reported)'}")
    except MediaError as error:
        # The code is what to branch on. `provider_failed` is the only one that
        # may correspond to work a provider actually attempted and charged for.
        print(f"\nFAILED  code={error.code}", file=sys.stderr)
        print(f"        {error}", file=sys.stderr)
        diagnostics = error.diagnostics
        print(f"        origin={diagnostics.origin}{diagnostics.path}", file=sys.stderr)
        if diagnostics.request_id:
            print(f"        request_id={diagnostics.request_id}", file=sys.stderr)
        # Headers print with every credential value already redacted.
        print(f"        headers={diagnostics.headers}", file=sys.stderr)
        return 1

    print("\nBoth generations completed. The control origin never saw either prompt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
