# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from unittest import mock

import pytest

from deploy import signing

# the test settings have no readable server chain; enrollment tokens need pins
TEST_PINS = ["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]


@pytest.fixture(autouse=True)
def server_pins(request):
    if getattr(request.cls, "real_pins", False):
        yield
        return
    with mock.patch.object(signing, "spki_pins", return_value=list(TEST_PINS)):
        yield
