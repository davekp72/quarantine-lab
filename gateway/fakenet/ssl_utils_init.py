# Copyright 2026 Google LLC
# Quarantine lab patch:
# - Avoid removed OpenSSL.crypto.X509Extension (modern pyOpenSSL).
# - Mint TLS *leaf* certs signed by the lab mitmproxy CA (never present the CA as the site cert).
# - CDP points at a CRL we serve on FakeNet HTTP (Schannel CRYPT_E_NO_REVOCATION_CHECK).
# - Validity clamped to the CA window (SEC_E_CERT_EXPIRED).

import os
import re
import ssl
import sys
import shutil
import logging
import traceback
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _cert_times(cert):
    nb = getattr(cert, "not_valid_before_utc", None) or _as_utc(cert.not_valid_before)
    na = getattr(cert, "not_valid_after_utc", None) or _as_utc(cert.not_valid_after)
    return nb, na


def _load_x509(path):
    with open(path, "rb") as f:
        data = f.read()
    # mitmproxy-ca.pem is key+cert; load_pem_x509_certificate uses the cert block.
    return x509.load_pem_x509_certificate(data)


def _cdp_uris(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []
    uris = []
    for dp in ext.value:
        if not dp.full_name:
            continue
        for name in dp.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                uris.append(name.value)
    return uris


def _validity_window(ca_cert_obj=None, leaf_days=825):
    # Windows Schannel uses the *guest* clock. Gateway RTC is often wrong in
    # FakeNet (no WAN/NTP). Never trust a 1970/insane now for notAfter.
    now = _utc_now()
    clock_ok = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc) <= now <= datetime.datetime(
        2038, 1, 1, tzinfo=datetime.timezone.utc
    )
    ca_nb = ca_na = None
    if ca_cert_obj is not None:
        ca_nb, ca_na = _cert_times(ca_cert_obj)

    if not clock_ok:
        if ca_nb and ca_na and (ca_na - ca_nb) > datetime.timedelta(days=2):
            return ca_nb + datetime.timedelta(hours=1), ca_na - datetime.timedelta(hours=1)
        return (
            datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            datetime.datetime(2035, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc),
        )

    nb = now - datetime.timedelta(minutes=5)
    na = now + datetime.timedelta(days=leaf_days)
    if ca_nb:
        nb = max(nb, ca_nb + datetime.timedelta(minutes=1))
    if ca_na:
        na = min(na, ca_na - datetime.timedelta(hours=1))
    if na <= nb:
        if ca_nb and ca_na and ca_na > ca_nb + datetime.timedelta(hours=2):
            return ca_nb + datetime.timedelta(hours=1), ca_na - datetime.timedelta(hours=1)
        nb = now - datetime.timedelta(minutes=5)
        na = now + datetime.timedelta(days=365)
    return nb, na


def _apply_cert_validity(builder, nb, na):
    if hasattr(builder, "not_valid_before_utc"):
        return builder.not_valid_before_utc(nb).not_valid_after_utc(na)
    return builder.not_valid_before(nb).not_valid_after(na)


def _apply_crl_validity(builder, this_update, next_update):
    if hasattr(builder, "last_update_utc"):
        return builder.last_update_utc(this_update).next_update_utc(next_update)
    return builder.last_update(this_update).next_update(next_update)


def default_cdp_urls(primary=None):
    urls = []
    if primary:
        urls.append(primary.strip())
    try:
        with open("/etc/quarantine-gateway/fakenet-cdp.url", "r") as f:
            hint = f.read().strip()
        if hint and hint not in urls:
            urls.insert(0, hint)
    except OSError:
        pass
    if not urls:
        urls.append("http://10.66.0.1/mitmproxy-ca.crl")
    # Single-label name: WinINET <local> proxy bypass; FakeNet DNS sinkholes it.
    extra = "http://mitmproxycrl/mitmproxy-ca.crl"
    if extra not in urls:
        urls.append(extra)
    return urls


def publish_mitm_crl(ca_cert_path, ca_key_path, dests):
    """Write a DER CRL (empty revoked list) signed by the lab MITM CA."""
    ca = _load_x509(ca_cert_path)
    with open(ca_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    this_update, next_update = _validity_window(ca)
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
    builder = _apply_crl_validity(builder, this_update, next_update)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False,
    )
    try:
        builder = builder.add_extension(x509.CRLNumber(1), critical=False)
    except Exception:
        pass
    hash_alg = hashes.SHA256()
    if isinstance(key, ed25519.Ed25519PrivateKey):
        hash_alg = None
    crl = builder.sign(private_key=key, algorithm=hash_alg)
    der = crl.public_bytes(serialization.Encoding.DER)
    written = []
    for dest in dests:
        if not dest:
            continue
        try:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            with open(dest, "wb") as f:
                f.write(der)
            written.append(dest)
        except OSError:
            traceback.print_exc()
    return written


class SSLWrapper(object):
    CN = "fakenet.flare"
    LEAF_DAYS = 825

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None
        self.ca_crl = None
        self.ca_cn = self.CN

        cert_dir = self.abs_config_path(self.config.get("cert_dir", None))
        if cert_dir is None:
            raise RuntimeError("cert_dir key is not specified in config")
        os.makedirs(cert_dir, exist_ok=True)

        static = str(self.config.get("static_ca") or "no").lower() == "yes"
        if static:
            self.ca_cert = self.abs_config_path(self.config.get("ca_cert", None))
            self.ca_key = self.abs_config_path(self.config.get("ca_key", None))
            if not self.ca_cert or not os.path.isfile(self.ca_cert):
                raise RuntimeError("static_ca=yes but ca_cert is missing")
            if not self.ca_key or not os.path.isfile(self.ca_key):
                raise RuntimeError("static_ca=yes but ca_key is missing")
            ca = _load_x509(self.ca_cert)
            try:
                self.ca_cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                self.ca_cn = "mitmproxy"
            nb, na = _cert_times(ca)
            now = _utc_now()
            self.logger.info("Using static MITM CA CN=%s valid %s .. %s", self.ca_cn, nb, na)
            if 2024 <= now.year <= 2038 and na is not None and now > na:
                self.logger.error(
                    "MITM CA is expired (%s). Re-create it (run permissive MITM once) "
                    "and reinstall the CA in the Windows guest.",
                    na,
                )
            self._publish_crl()
        else:
            self.ca_cert, self.ca_key, self.ca_crl = self.create_cert(self.CN)
            self._publish_crl()

    def wrap_socket(self, s):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        except AttributeError:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1
        ctx.sni_callback = self.sni_callback
        leaf, key = self._leaf_for(self.config.get("default_cn") or "fakenet.local")
        ctx.load_cert_chain(certfile=leaf, keyfile=key)
        return ctx.wrap_socket(s, server_side=True)

    def sni_callback(self, sslsock, servername, sslctx):
        name = servername or self.CN
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        leaf, key = self._leaf_for(name)
        try:
            newctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        except AttributeError:
            newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        newctx.options |= ssl.OP_NO_TLSv1
        newctx.options |= ssl.OP_NO_TLSv1_1
        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=leaf, keyfile=key)
        sslsock.context = newctx

    def _leaf_for(self, cn):
        cert_file, key_file, _ = self.create_cert(cn, self.ca_cert, self.ca_key)
        if not cert_file or not key_file:
            raise RuntimeError("failed to mint FakeNet leaf for %r" % (cn,))
        return cert_file, key_file

    def _safe_name(self, cn):
        cn = cn.decode("utf-8", "replace") if isinstance(cn, bytes) else str(cn)
        cn = cn.strip().strip(".").lower() or "fakenet.local"
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", cn)[:180]

    def _cached_leaf_ok(self, cert_file, key_file):
        if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
            return False
        try:
            cert = _load_x509(cert_file)
        except Exception:
            return False
        want = set(self._cdp_urls())
        have = set(_cdp_uris(cert))
        if not want.intersection(have):
            return False
        # Must be an end-entity cert, not the CA itself.
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bc.ca:
                return False
        except x509.ExtensionNotFound:
            pass
        nb, na = _cert_times(cert)
        now = _utc_now()
        clock_ok = 2024 <= now.year <= 2038
        # Gateway RTC is often 1970 in FakeNet. A leaf dated in the CA's real
        # window is still valid on the Windows guest.
        if clock_ok:
            if nb and now < nb - datetime.timedelta(minutes=5):
                return False
            if na and now > na - datetime.timedelta(days=7):
                return False
        elif na is None or na.year < 2024:
            return False
        return True

    def create_cert(self, cn, ca_cert=None, ca_key=None, cert_dir=None):
        """
        Create a leaf (or self-signed CA when ca_* omitted).

        Returns (chain_or_cert_pem, key_file, crl_file).
        For signed leaves, the first path is leaf+CA fullchain for load_cert_chain.
        """
        f_selfsign = ca_cert is None or ca_key is None
        if not cert_dir:
            cert_dir = self.abs_config_path(self.config.get("cert_dir"))
        else:
            cert_dir = os.path.abspath(cert_dir)
        os.makedirs(cert_dir, exist_ok=True)

        safe = self._safe_name(cn)
        cert_file = os.path.join(cert_dir, "%s.crt" % safe)
        key_file = os.path.join(cert_dir, "%s.key" % safe)
        chain_file = os.path.join(cert_dir, "%s.chain.pem" % safe)
        crl_file = os.path.join(cert_dir, "ca.crl")

        if f_selfsign:
            if self._cached_leaf_ok(cert_file, key_file):
                return cert_file, key_file, crl_file
            self._mint_self_signed(cn, cert_file, key_file, crl_file)
            return cert_file, key_file, crl_file

        if self._cached_leaf_ok(cert_file, key_file) and os.path.isfile(chain_file):
            return chain_file, key_file, crl_file

        self._mint_leaf(cn, cert_file, key_file, chain_file, ca_cert, ca_key)
        self._publish_crl()
        return chain_file, key_file, crl_file

    def _validity_window(self, ca_cert_obj=None):
        return _validity_window(ca_cert_obj, self.LEAF_DAYS)

    def _cdp_urls(self):
        primary = (self.config.get("crl_url") or self.config.get("cdp_url") or "").strip()
        return default_cdp_urls(primary or None)

    def _publish_crl(self):
        if not self.ca_cert or not self.ca_key:
            return
        dests = [
            os.path.join(self.abs_config_path(self.config.get("cert_dir")), "ca.crl"),
            "/var/log/quarantine/fakenet/www/mitmproxy-ca.crl",
            "/etc/quarantine-gateway/mitmproxy-ca.crl",
        ]
        wr = self.config.get("webroot")
        if wr:
            dests.append(os.path.join(str(wr), "mitmproxy-ca.crl"))
        written = publish_mitm_crl(self.ca_cert, self.ca_key, dests)
        if written:
            self.ca_crl = written[0]
            self.logger.info("Published MITM CRL to %s", ", ".join(written))

    def _mint_self_signed(self, cn, cert_file, key_file, crl_file):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nb, na = self._validity_window(None)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, str(cn)[:64]),
        ])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(ski, critical=False)
        )
        builder = _apply_cert_validity(builder, nb, na)
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
        self._write_key(key_file, key)
        self._write_cert(cert_file, cert)
        crl_builder = x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
        crl_builder = _apply_crl_validity(crl_builder, nb, na)
        try:
            crl = crl_builder.sign(private_key=key, algorithm=hashes.SHA256())
            with open(crl_file, "wb") as f:
                f.write(crl.public_bytes(serialization.Encoding.DER))
        except Exception:
            traceback.print_exc()

    def _mint_leaf(self, cn, cert_file, key_file, chain_file, ca_cert, ca_key):
        ca_cert_obj = _load_x509(ca_cert)
        with open(ca_key, "rb") as f:
            ca_key_obj = serialization.load_pem_private_key(f.read(), password=None)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nb, na = self._validity_window(ca_cert_obj)
        cn_str = cn.decode("utf-8", "replace") if isinstance(cn, bytes) else str(cn)
        cn_str = cn_str.strip().strip(".") or "fakenet.local"
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn_str[:64]),
        ])
        san = self._san_for(cn_str)
        ski = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key_obj.public_key())
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert_obj.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(san, critical=False)
            .add_extension(ski, critical=False)
            .add_extension(aki, critical=False)
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(url)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                        for url in self._cdp_urls()
                    ]
                ),
                critical=False,
            )
        )
        builder = _apply_cert_validity(builder, nb, na)
        hash_alg = hashes.SHA256()
        if isinstance(ca_key_obj, (ed25519.Ed25519PrivateKey,)):
            hash_alg = None
        cert = builder.sign(private_key=ca_key_obj, algorithm=hash_alg)
        self._write_key(key_file, leaf_key)
        self._write_cert(cert_file, cert)
        with open(ca_cert, "rb") as f:
            ca_pem = f.read()
        # Full chain: leaf first, then the lab MITM CA (same cert the guest should trust).
        with open(chain_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            if not ca_pem.endswith(b"\n"):
                f.write(b"\n")
            f.write(ca_pem)
        encoded_nb, encoded_na = _cert_times(cert)
        self.logger.info("Minted FakeNet leaf CN=%s valid %s .. %s", cn_str, encoded_nb, encoded_na)
        if encoded_na is not None and encoded_na.year < 2024:
            raise RuntimeError("minted leaf notAfter is %s (refusing to serve an expired cert)" % encoded_na)

    def _san_for(self, cn):
        names = []
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(cn)))
        except Exception:
            try:
                names.append(x509.DNSName(cn))
            except ValueError:
                names.append(x509.DNSName("fakenet.local"))
        if not any(isinstance(n, x509.DNSName) and n.value == "fakenet.local" for n in names):
            try:
                names.append(x509.DNSName("fakenet.local"))
            except ValueError:
                pass
        return x509.SubjectAlternativeName(names)

    def _write_cert(self, path, cert):
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _write_key(self, path, key):
        with open(path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    def abs_config_path(self, path):
        if path is None:
            return None
        if os.path.isabs(path):
            return path
        abspath = os.path.abspath(path)
        if os.path.exists(abspath):
            return abspath
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            abspath = os.path.join(os.getcwd(), path)
        else:
            abspath = os.path.join(os.fspath(Path(__file__).parents[2]), path)
        return abspath

    def __del__(self):
        # Do not delete cert_dir when using the lab MITM CA — FakeNet may still be serving.
        try:
            static = str(self.config.get("static_ca") or "no").lower() == "yes"
            if static:
                return
            shutil.rmtree(self.abs_config_path(self.config.get("cert_dir", None)), ignore_errors=True)
        except Exception:
            pass
