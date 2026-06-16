import json
import pathlib

import pytest

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "cert.json"


@pytest.fixture
def cert_fixture():
    return json.loads(FIXTURE.read_text())
