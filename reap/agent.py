"""Operator-side provisioning for the standalone lab agent."""
from __future__ import annotations

import datetime
import secrets
import shutil
from pathlib import Path


def prepare_bundle(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from .data import reap_agent

    destination = Path(directory)
    # Never overwrite an existing identity or token.
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Reap lab agent')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    contents = {
        '.gitignore': b'*\n',
        'cert.pem': cert.public_bytes(serialization.Encoding.PEM),
        'key.pem': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()),
        'token.txt': (secrets.token_urlsafe(32) + '\n').encode(),
        'fingerprint.txt': (cert.fingerprint(hashes.SHA256()).hex() + '\n').encode(),
    }
    for filename, data in contents.items():
        path = destination / filename
        path.write_bytes(data)
        path.chmod(0o600)
    shutil.copyfile(reap_agent.__file__, destination / 'reap_agent.py')
    return destination
