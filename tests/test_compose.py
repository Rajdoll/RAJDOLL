"""Guard the deployment rules from TRD 2.2 and 9 against accidental changes."""

from pathlib import Path

import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parent.parent / "compose.yaml").read_text())


def test_exactly_four_services() -> None:
    assert set(COMPOSE["services"]) == {"api", "worker", "tools", "db"}


def test_only_api_publishes_ports_and_only_on_localhost() -> None:
    services = COMPOSE["services"]
    for name, service in services.items():
        if name == "api":
            continue
        assert "ports" not in service, f"{name} must not publish ports to the host"
    for mapping in services["api"]["ports"]:
        assert str(mapping).startswith("127.0.0.1:"), f"api port {mapping} must bind to localhost"


def test_database_password_is_required() -> None:
    password = COMPOSE["services"]["db"]["environment"]["POSTGRES_PASSWORD"]
    assert password.startswith("${POSTGRES_PASSWORD:?")


def test_internal_secrets_are_required() -> None:
    api_env = COMPOSE["services"]["api"]["environment"]
    tools_env = COMPOSE["services"]["tools"]["environment"]
    assert api_env["RAJDOLL_TOOLS_TOKEN"].startswith("${TOOLS_TOKEN:?")
    assert api_env["RAJDOLL_TOOLS_DB_PASSWORD"].startswith("${TOOLS_DB_PASSWORD:?")
    assert tools_env["RAJDOLL_TOOLS_TOKEN"].startswith("${TOOLS_TOKEN:?")


def test_tools_container_cannot_see_app_secrets() -> None:
    tools = COMPOSE["services"]["tools"]
    mounts = [str(v).split(":")[0] for v in tools.get("volumes", [])]
    assert "secrets" not in mounts
    assert "RAJDOLL_SECRETS_DIR" not in tools["environment"]
    assert "rajdoll_app" not in tools["environment"]["RAJDOLL_PROXY_DATABASE_URL"]


def test_only_api_gets_the_tools_role_password() -> None:
    worker_env = COMPOSE["services"]["worker"]["environment"]
    assert "RAJDOLL_TOOLS_DB_PASSWORD" not in worker_env
