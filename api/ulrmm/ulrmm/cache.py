# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.cache.backends.dummy import DummyCache
from django.core.cache.backends.redis import RedisCache

# raw keys are stored as ":<version>:<key>" (empty KEY_PREFIX, version default 1)
_DELETE_BATCH = 500


class ULRMMRedisCache(RedisCache):
    def _raw_client(self):
        return self._cache.get_client(None)

    def _match(self, pattern, version):
        return f":{version or 1}:{pattern}"

    def delete_many_pattern(self, pattern, version=None):
        client = self._raw_client()
        match = self._match(pattern, version)
        batch = []
        for key in client.scan_iter(match=match):
            batch.append(key)
            if len(batch) >= _DELETE_BATCH:
                client.delete(*batch)
                batch = []
        if batch:
            client.delete(*batch)

    def iter_keys_pattern(self, pattern, version=None):
        yield from self._raw_client().scan_iter(match=self._match(pattern, version))


class ULRMMDummyCache(DummyCache):
    def delete_many_pattern(self, pattern, version=None):
        return None

    def iter_keys_pattern(self, pattern, version=None):
        return iter(())
