import importlib.util
from pathlib import Path
from types import ModuleType

IN_IMAGE_PY = Path(__file__).resolve().parent.parent / "bench" / "in_image.py"


def load_wrapper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_in_image", IN_IMAGE_PY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wrapper = load_wrapper()


def test_loopback_urls_point_at_the_container_host_and_paths_move_into_the_image() -> (
    None
):
    argv = [
        "--url", "http://127.0.0.1:13000/",
        "--output", "/tmp/results/juice_shop/raw/runs/run1",
        "--allow-private",
        "--config", "/tmp/xyz/auth.yaml",
    ]  # fmt: skip
    args, output, config = wrapper.container_args(argv)
    assert args == [
        "--url", f"http://{wrapper.HOST_ALIAS}:13000/",
        "--output", wrapper.REPORT_DIR,
        "--allow-private",
        "--config", wrapper.CONFIG_PATH,
    ]  # fmt: skip
    assert output == Path("/tmp/results/juice_shop/raw/runs/run1")
    assert config == Path("/tmp/xyz/auth.yaml")


def test_argv_without_output_or_config_is_only_rewritten() -> None:
    args, output, config = wrapper.container_args(["--url", "http://localhost:80"])
    assert args == ["--url", f"http://{wrapper.HOST_ALIAS}:80"]
    assert output is None
    assert config is None
