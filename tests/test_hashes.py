import base64
import sys
import types

import pytest

from reap.correlation import CorrelationEngine
from reap.hashes import format_hash
from reap.store import LootStore


@pytest.mark.parametrize('kind,secret,mode', [
    ('bcrypt', '$2b$12$' + 'a' * 53, '3200'),
    ('sha512crypt', '$6$salt$' + 'a' * 86, '1800'),
    ('sha256crypt', '$5$rounds=5000$salt$' + 'a' * 43, '7400'),
    ('md5crypt', '$1$salt$' + 'a' * 22, '500'),
    ('ntlm', 'a' * 32 + ':' + 'b' * 32, '1000'),
    ('mssql_2012', '0x0200' + 'a' * 136, '1731'),
    ('mssql_2005', '0x0100' + 'a' * 48, '132'),
])
def test_supported_hash_formats(kind, secret, mode):
    result_mode, result, description = format_hash({'secret': secret, 'metadata': {'hash_type': kind}})
    assert result_mode == mode and description
    assert result == ('b' * 32 if kind == 'ntlm' else secret)


def test_postgres_scram_requires_complete_verifier():
    encoded = base64.b64encode(b'k' * 32).decode()
    value = 'SCRAM-SHA-256$4096:c2FsdA==$%s:%s' % (encoded, encoded)
    assert format_hash({'secret': value, 'metadata': {'hash_type': 'postgres_scram_sha256'}})[0] == '28600'
    with pytest.raises(ValueError):
        format_hash({'secret': value[:-10], 'metadata': {'hash_type': 'postgres_scram_sha256'}})


def test_mongo_collection_uses_server_key_and_base64_username(tmp_path, monkeypatch):
    stored = base64.b64encode(b't' * 32).decode()
    server = base64.b64encode(b's' * 32).decode()
    docs = [{'user': 'lab*user', 'credentials': {'SCRAM-SHA-256': {
        'iterationCount': 15000, 'salt': 'c2FsdA==', 'storedKey': stored, 'serverKey': server}}}]

    class Client:
        def __init__(self, **kwargs):
            self.admin = types.SimpleNamespace(system=types.SimpleNamespace(users=self))
        def find(self, *args, **kwargs):
            return docs
        def close(self):
            pass

    monkeypatch.setitem(sys.modules, 'pymongo', types.SimpleNamespace(MongoClient=Client))
    engine = CorrelationEngine(LootStore(str(tmp_path / 'loot.db')))
    user, value, metadata = engine._dump_mongodb('fixture', 27017, 'user', 'secret')[0]
    assert stored not in value and server in value
    assert '*bGFiKnVzZXI=*15000*' in value
    assert format_hash({'secret': value, 'metadata': metadata})[0] == '24200'
    with pytest.raises(ValueError, match='recollect'):
        format_hash({'secret': '$mongodb-scram$1$user$1000$salt$stored',
                     'metadata': {'hash_type': 'mongodb_scram_sha256'}})
