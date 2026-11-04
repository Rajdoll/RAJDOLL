from multi_agent_system.framework.types import EndpointSpec, Payload


def test_endpoint_spec_required_fields():
    ep = EndpointSpec(url="http://example.com/api", method="POST", params=["q"])
    assert ep.url == "http://example.com/api"
    assert ep.method == "POST"
    assert ep.params == ["q"]
    assert ep.content_type is None


def test_payload_required_fields():
    p = Payload(value="{{7*7}}", encoding="raw", expected_signal="49", category="ssti")
    assert p.value == "{{7*7}}"
    assert p.encoding == "raw"
    assert p.expected_signal == "49"
    assert p.category == "ssti"
    assert p.engine_hypothesis is None


def test_payload_with_engine_hypothesis():
    p = Payload(value="<%=7*7%>", encoding="raw", expected_signal="49",
                category="ssti", engine_hypothesis="erb")
    assert p.engine_hypothesis == "erb"
