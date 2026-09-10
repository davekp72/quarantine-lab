# Copyright 2026 Google LLC
# Quarantine lab copy of FakeNet HTTPListener with CONNECT (browser HTTPS via PAC).
# QUARANTINE_CONNECT_PATCH_V3

import logging
from configparser import ConfigParser

import os
import sys
import importlib.util
import importlib.machinery

import threading
import socketserver
import http.server

import ssl
import socket

import posixpath
import mimetypes

import time

from .ssl_utils import SSLWrapper
from . import *

MIME_FILE_RESPONSE = {
    "text/html": "FakeNet.html",
    "image/png": "FakeNet.png",
    "image/ico": "FakeNet.ico",
    "image/jpeg": "FakeNet.jpg",
    "application/octet-stream": "FakeNetMini.exe",
    "application/x-msdownload": "FakeNetMini.exe",
    "application/x-msdos-program": "FakeNetMini.exe",
    "application/pdf": "FakeNet.pdf",
    "application/xml": "FakeNet.html",
}

INDENT = " "


def qualify_file_path(filename, fallbackdir):
    path = filename
    if path:
        if not os.path.exists(path):
            path = os.path.join(fallbackdir, filename)
            if not os.path.exists(path):
                raise RuntimeError("Cannot find %s" % (filename))
    return path


def load_source(modname, filename):
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CustomResponse(object):
    def __init__(self, name, conf, configroot):
        self.name = name
        match_specs = {"httpuris", "httphosts"}
        response_specs = {"httprawfile", "httpstaticstring", "httpdynamic"}
        if not match_specs.intersection(conf):
            raise ValueError(
                "Custom HTTP config section %s lacks %s" % (name, "/".join(match_specs))
            )
        nr_responses = len(response_specs.intersection(conf))
        if nr_responses != 1:
            raise ValueError(
                "Custom HTTP config section %s has %d of %s"
                % (name, nr_responses, "/".join(response_specs))
            )
        if ("contenttype" in conf) and ("httpstaticstring" not in conf):
            raise ValueError(
                "Custom HTTP config section %s has ContentType which is only usable with HttpStaticString"
                % (name)
            )
        self.uris = conf.get("httpuris", {})
        if self.uris:
            self.uris = {u.strip() for u in self.uris.split(",")}
        self.hosts = conf.get("httphosts", {})
        if self.hosts:
            self.hosts = {h.strip().lower() for h in self.hosts.split(",")}
        self.raw_file = qualify_file_path(conf.get("httprawfile"), configroot)
        if self.raw_file:
            self.raw_file = open(self.raw_file, "rb").read()
        self.handler = None
        pymod_path = qualify_file_path(conf.get("httpdynamic"), configroot)
        if pymod_path:
            pymod = load_source("cr_" + self.name, pymod_path)
            funcname = "HandleHttp"
            funcname_legacy = "HandleRequest"
            if hasattr(pymod, funcname):
                self.handler = getattr(pymod, funcname)
            elif hasattr(pymod, funcname_legacy):
                self.handler = getattr(pymod, funcname_legacy)
            else:
                raise ValueError(
                    "Loaded %s module %s has no function %s"
                    % ("httpdynamic", conf.get("httpdynamic"), funcname)
                )
        self.static_string = conf.get("httpstaticstring")
        if self.static_string is not None:
            self.static_string = self.static_string.replace("\\r\\n", "\r\n")
            self.content_type = conf.get("ContentType")

    def checkMatch(self, host, uri):
        hostmatch = host.strip().lower() in self.hosts
        if (not hostmatch) and (":" in host):
            host = host[: host.find(":")]
            hostmatch = host.strip().lower() in self.hosts
        urimatch = False
        for match_uri in self.uris:
            if uri.endswith(match_uri):
                urimatch = True
                break
        if self.uris and self.hosts:
            return hostmatch and urimatch
        return hostmatch or urimatch

    def respond(self, req, meth, postdata=None):
        current_time = req.date_time_string()
        if self.raw_file:
            up_to_date = self.raw_file.replace(b"<RAW-DATE>", current_time.encode("utf-8"))
            req.wfile.write(up_to_date)
        elif self.handler:
            self.handler(req, meth, postdata)
        elif self.static_string is not None:
            up_to_date = self.static_string.replace("<RAW-DATE>", current_time)
            req.send_response(200)
            req.send_header("Content-Length", len(up_to_date))
            if self.content_type:
                req.send_header("Content-Type", self.content_type)
            req.end_headers()
            req.wfile.write(up_to_date.encode("utf-8"))


class HTTPListener(object):
    def taste(self, data, dport):
        request_methods = [
            b"GET",
            b"HEAD",
            b"POST",
            b"PUT",
            b"DELETE",
            b"TRACE",
            b"OPTIONS",
            b"CONNECT",
            b"PATCH",
        ]
        confidence = 1 if dport in [80, 443, 8080, 8081] else 0
        for method in request_methods:
            if data.lstrip().startswith(method):
                confidence += 2
                continue
        return confidence

    if not mimetypes.inited:
        mimetypes.init()
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({"": "text/html"})

    def __init__(self, config={}, name="HTTPListener", logging_level=logging.DEBUG):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
        self.config = config
        self.name = name
        self.local_ip = config.get("ipaddr")
        self.server = None
        self.port = self.config.get("port", 80)
        self.sslwrapper = None
        self.logger.debug("Initialized with config:")
        for key, value in config.items():
            self.logger.debug(" %10s: %s", key, value)
        path = self.config.get("webroot", "defaultFiles")
        self.webroot_path = ListenerBase.abs_config_path(path)
        if self.webroot_path is None:
            self.logger.error("Could not locate webroot directory: %s", path)
            sys.exit(1)

    def start(self):
        self.logger.debug("Starting...")
        self.server = ThreadedHTTPServer(
            (self.local_ip, int(self.config.get("port"))), ThreadedHTTPRequestHandler
        )
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

        usessl = str(self.config.get("usessl") or "No")
        static_ca = str(self.config.get("static_ca") or "No").lower() == "yes"
        if usessl == "Yes" or static_ca:
            ssl_cfg = {
                "cert_dir": self.config.get("cert_dir", os.path.join("configs", "temp_certs")),
                "networkmode": self.config.get("networkmode", None),
                "static_ca": self.config.get("static_ca", "No"),
                "ca_cert": self.config.get("ca_cert"),
                "ca_key": self.config.get("ca_key"),
                "webroot": self.webroot_path,
            }
            self.sslwrapper = SSLWrapper(ssl_cfg)
            self.server.sslwrapper = self.sslwrapper
            if usessl == "Yes":
                self.logger.debug("HTTP Listener starting with SSL")
                self.server.socket = self.sslwrapper.wrap_socket(self.server.socket)

        self.server.custom_responses = []
        custom = self.config.get("custom")

        def checkSetting(d, name, value):
            if name not in d:
                return False
            return d[name].lower() == value.lower()

        if custom:
            configdir = self.config.get("configdir")
            custom = qualify_file_path(custom, configdir)
            customconf = ConfigParser()
            customconf.read(custom)
            for section in customconf.sections():
                entries = dict(customconf.items(section))
                if ("instancename" not in entries) and ("listenertype" not in entries):
                    raise RuntimeError("Custom Response lacks ListenerType or InstanceName")
                if checkSetting(entries, "instancename", self.name) or checkSetting(
                    entries, "listenertype", "HTTP"
                ):
                    cr = CustomResponse(section, entries, configdir)
                    self.server.custom_responses.append(cr)

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug("Stopping...")
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.server.diverterListenerCallbacks = diverterListenerCallbacks


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exctype, value = sys.exc_info()[:2]
        self.logger.error("Error: %s", value)


class ThreadedHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args):
        http.server.BaseHTTPRequestHandler.__init__(self, *args)
        self.logger = self.server.logger

    def version_string(self):
        return self.server.config.get("version", "FakeNet/1.3")

    def setup(self):
        self.request.settimeout(int(self.server.config.get("timeout", 10)))
        http.server.BaseHTTPRequestHandler.setup(self)

    def do_CONNECT(self):
        # QUARANTINE_CONNECT_PATCH_V3
        # Browser HTTPS: CONNECT host:443 then TLS on this same socket.
        # Never close rfile/wfile — makefile.close() closes the client socket.
        dest = getattr(self, "path", "") or "fakenet.local"
        host = dest.split("/")[0]
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        host = host.strip() or "fakenet.local"
        self.server.logger.info("CONNECT %s", dest)
        wrapper = getattr(self.server, "sslwrapper", None)
        self.close_connection = True

        def _detach(f):
            if f is None:
                return
            try:
                inner = f.detach()
            except Exception:
                return
            try:
                inner.detach()
            except Exception:
                pass

        try:
            self.wfile.flush()
        except Exception:
            pass
        _detach(getattr(self, "rfile", None))
        _detach(getattr(self, "wfile", None))
        try:
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            return
        if wrapper is None:
            self.server.logger.error("CONNECT: no SSLWrapper (set Static_CA Yes)")
            return
        try:
            wrap = getattr(wrapper, "wrap_accepted_socket", None)
            if wrap is not None:
                ssock = wrap(self.connection, host)
            else:
                ssock = wrapper.wrap_socket(self.connection)
            self.connection = ssock
            self.request = ssock
            self.rfile = ssock.makefile("rb", -1)
            self.wfile = ssock.makefile("wb", 0)
            self.handle_one_request()
            while not self.close_connection:
                self.handle_one_request()
            try:
                self.wfile.flush()
            except Exception:
                pass
        except Exception as exc:
            self.server.logger.error("CONNECT TLS: %s", exc)

    def doCustomResponse(self, meth, post_data=None):
        uri = self.path
        host = self.headers.get("host", "")
        for cr in self.server.custom_responses:
            if cr.checkMatch(host, uri):
                self.server.logger.debug("Invoking custom response %s" % (cr.name))
                cr.respond(self, meth, post_data)
                return True
        return False

    def do_HEAD(self):
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)
        self.collect_nbi(self.requestline, self.headers)
        if not self.doCustomResponse("HEAD"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

    def do_GET(self):
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)
        self.collect_nbi(self.requestline, self.headers)
        if not self.doCustomResponse("GET"):
            response, response_type = self.get_response(self.path)
            self.send_response(200)
            self.send_header("Content-Type", response_type)
            self.send_header("Content-Length", len(response))
            self.end_headers()
            self.wfile.write(response)

    def do_POST(self):
        content_len = int(self.headers.get("content-length", 0))
        post_body = self.rfile.read(content_len)
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)
        self.collect_nbi(self.requestline, self.headers, post_body)
        if self.server.config.get("dumphttpposts") and self.server.config["dumphttpposts"].lower() == "yes":
            http_filename = "%s_%s.txt" % (
                self.server.config.get("dumphttppostsfileprefix", "http"),
                time.strftime("%Y%m%d_%H%M%S"),
            )
            self.server.logger.info("Storing HTTP POST headers and data to %s.", http_filename)
            http_f = open(http_filename, "wb")
            if http_f:
                http_f.write(self.requestline.encode("utf-8") + b"\r\n")
                http_f.write(str(self.headers).encode("utf-8") + b"\r\n")
                http_f.write(post_body)
                http_f.close()
        if not self.doCustomResponse("GET", post_body):
            response, response_type = self.get_response(self.path)
            self.send_response(200)
            self.send_header("Content-Type", response_type)
            self.send_header("Content-Length", len(response))
            self.end_headers()
            self.wfile.write(response)

    def collect_nbi(self, requestline, headers, post_data=None):
        nbi = {}
        method, uri, version = requestline.split(" ")
        nbi["Method"] = method
        nbi["URI"] = uri
        nbi["Version"] = version
        for line in str(headers).rstrip().split("\n"):
            key, _, value = line.partition(":")
            nbi[key] = value.lstrip()
        if post_data:
            nbi["Request Body"] = post_data
        cb = getattr(self.server, "diverterListenerCallbacks", None)
        if cb:
            cb.logNbi(
                self.client_address[1],
                nbi,
                "TCP",
                "HTTP",
                self.server.config.get("usessl"),
            )

    def get_response(self, path):
        response = b"<html><head><title>FakeNet</title></head><body><h1>FakeNet</h1></body></html>"
        response_type = "text/html"
        if path[-1] == "/":
            response_type = "text/html"
            path += "index.html"
        else:
            _, ext = posixpath.splitext(path)
            response_type = self.server.extensions_map.get(ext, "text/html")
        response_filename = ListenerBase.safe_join(self.server.webroot_path, path)
        if not os.path.exists(response_filename):
            self.server.logger.debug("Could not find path: %s", response_filename)
            response_filename = os.path.join(
                self.server.webroot_path, MIME_FILE_RESPONSE.get(response_type, "FakeNet.html")
            )
            if not os.path.exists(response_filename):
                self.server.logger.debug("Could not find path: %s", response_filename)
                return (response, response_type)
        self.server.logger.debug(
            "Responding with mime type: %s file: %s", response_type, response_filename
        )
        try:
            f = open(response_filename, "rb")
        except Exception:
            self.server.logger.error("Failed to open response file: %s", response_filename)
            response_type = "text/html"
        else:
            response = f.read()
            f.close()
        return (response, response_type)

    def log_message(self, format, *args):
        return
