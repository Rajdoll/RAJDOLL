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
