from telegent import HttpRequest, is_llm_request, is_streaming_token_event


def test_default_llm_request_classifier() -> None:
    cases = (
        (HttpRequest("POST", "/responses"), True),
        (HttpRequest("post", "/v1/responses?beta=true"), True),
        (HttpRequest("POST", "/api/v1/responses/"), True),
        (HttpRequest("POST", "/v1/chat/completions"), True),
        (HttpRequest("GET", "/v1/responses"), False),
        (HttpRequest("POST", "/openai/plugins.git/git-upload-pack"), False),
        (HttpRequest("POST", "/mcp"), False),
        (HttpRequest("POST", "/notresponses"), False),
    )

    assert tuple((request, is_llm_request(request)) for request, _ in cases) == cases


def test_streaming_token_event_classifier() -> None:
    cases = (
        (b'data: {"type":"response.output_text.delta"}', True),
        (
            b"event: response.reasoning_text.delta\n"
            b'data: {"type":"response.reasoning_text.delta"}',
            True,
        ),
        (
            b'data: {"type":\n'
            b'data: "response.reasoning_summary_text.delta"}',
            True,
        ),
        (b'data: {"type":"response.in_progress"}', False),
        (b": keepalive", False),
        (b"data: [DONE]", False),
        (b"data: invalid", False),
        (b"data: \xff", False),
    )

    assert tuple((event, is_streaming_token_event(event)) for event, _ in cases) == cases
