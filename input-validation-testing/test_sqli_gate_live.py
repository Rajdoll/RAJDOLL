import importlib.util, pathlib, asyncio, socket, pytest
_p = pathlib.Path(__file__).parent / "input-validation.py"
_s = importlib.util.spec_from_file_location("iv_mod_live", _p)
iv = importlib.util.module_from_spec(_s); _s.loader.exec_module(iv)

def _up(host, port):
    try:
        socket.create_connection((host, port), timeout=2).close(); return True
    except OSError:
        return False

JUICE = ("localhost", 3000)

@pytest.mark.skipif(not _up(*JUICE), reason="juice-shop not reachable")
def test_screen_signals_on_real_search_sqli():
    out = asyncio.run(
        iv._sqli_screen("http://localhost:3000/rest/products/search?q=apple", param="q")
    )
    assert out["signal"] is True   # ')-- yields SQLITE_ERROR on real juice-shop

@pytest.mark.skipif(not _up(*JUICE), reason="juice-shop not reachable")
def test_screen_no_signal_on_non_injectable_path():
    out = asyncio.run(
        iv._sqli_screen("http://localhost:3000/rest/products/1/reviews", param="id")
    )
    assert out["signal"] is False
