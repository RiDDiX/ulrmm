# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models

from ulrmm.constants import CORE_BRANDING_CACHE_KEY


class Branding(models.Model):
    """Instance white-labeling. Singleton.

    Kept out of CoreSettings so the logo data-URIs never enter the
    CoreSettings redis cache (read on agent paths) or the audit-log diffs.
    """

    product_name = models.CharField(max_length=255, default="UniversalLocal RMM")
    company_name = models.CharField(max_length=255, null=True, blank=True)
    support_url = models.CharField(
        max_length=500,
        null=True,
        blank=True,
        validators=[URLValidator(("http", "https"))],
    )
    # data URIs, e.g. "data:image/png;base64,..."; validated in the serializer
    logo = models.TextField(null=True, blank=True)
    favicon = models.TextField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "branding"

    def save(self, *args, **kwargs):
        if not self.pk and Branding.objects.exists():
            raise ValidationError("There can only be one Branding instance")

        super().save(*args, **kwargs)
        cache.delete(CORE_BRANDING_CACHE_KEY)

    def __str__(self):
        return self.product_name
