from telegent import HttpRequest, is_llm_request


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
