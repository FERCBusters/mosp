import pytest

import myf.host

myf.host.bind(
    name="testapp",
    title="TestApp",
    config="tests.testapp.config",
    hooks="tests.testapp.hooks",
)


@pytest.fixture
def hook():
    """Install application hooks for one test."""
    from tests.testapp import hooks

    def install(**functions):
        hooks.OVERRIDES.update(functions)

    yield install
    hooks.OVERRIDES.clear()
