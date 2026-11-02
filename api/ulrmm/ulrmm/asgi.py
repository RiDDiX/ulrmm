# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import os

from channels.routing import ProtocolTypeRouter, URLRouter  # isort:skip
from django.core.asgi import get_asgi_application  # isort:skip

# settings must be configured and apps loaded before the websocket routes import models
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ulrmm.settings")  # isort:skip
http_app = get_asgi_application()  # isort:skip

from ulrmm.utils import KnoxAuthMiddlewareStack  # isort:skip # noqa
from .urls import ws_urlpatterns  # isort:skip # noqa

websocket_app = KnoxAuthMiddlewareStack(URLRouter(ws_urlpatterns))
application = ProtocolTypeRouter({"http": http_app, "websocket": websocket_app})
