import pathlib

def test_juice_shop_image_pinned_to_v15():
    compose = (pathlib.Path(__file__).parents[3] / "docker-compose.yml").read_text()
    assert "bkimminich/juice-shop:v15.0.0" in compose
    assert "bkimminich/juice-shop:latest" not in compose
