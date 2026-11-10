import pytest
from conda.base.context import reset_context


@pytest.fixture(autouse=True)
def package_cache(tmp_path_factory, monkeypatch):
    """Keep conda's index cache for test channels out of the user's cache."""
    monkeypatch.setenv("CONDA_PKGS_DIRS", str(tmp_path_factory.getbasetemp() / "pkgs"))
    reset_context()
    yield
    monkeypatch.delenv("CONDA_PKGS_DIRS")
    reset_context()
