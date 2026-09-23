"""Installed-wheel transport/parser failure tests; no TPM or mocked crypto success."""
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
import confido


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.requests.append((self.path, self.headers.get('Authorization')))
        self.rfile.read(int(self.headers.get('Content-Length','0')))
        self.send_response(self.server.status)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(self.server.length or len(self.server.body)))
        self.end_headers()
        if not self.server.length:
            self.wfile.write(self.server.body)

    def do_GET(self):
        self.server.requests.append((self.path,self.headers.get('Authorization')))
        self.send_response(302)
        self.send_header('Location','https://other.invalid/service-info')
        self.end_headers()

    def log_message(self,*args): pass


class AppraisalApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cert=Path(cls.temp.name)/'cert.pem';key=Path(cls.temp.name)/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.server=HTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.config=json.loads((Path(__file__).resolve().parents[2]/'profiles/match.json').read_text())
        cls.config['origin']=f'https://localhost:{cls.server.server_port}'
        cls.preview={'id':cls.config['service_id'],'type':{'group':'network.genxt.demo','artifact':'confidential-chat','version':'0.2.0'},'version':'0.3.0','teeReport':{'profile':'azure-snp-vtpm-ima/1','wireVersion':1,'endpoint':'/tee-report','method':'POST','nonce':{'name':'nonce','in':'body','encoding':'base64','sizeBytes':32},'response':{'evidenceField':'evidence','certificateField':'certificate'},'sessionBinding':{'supported':False}}}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=5);cls.temp.cleanup()

    def setUp(self):
        self.server.body=b'not-json';self.server.status=200;self.server.length=None;self.server.requests=[]

    def connect(self,preview=None):
        session=confido.connect_py(json.dumps(self.config),json.dumps(preview or self.preview))
        r=json.loads(session.result_json)
        self.assertFalse(r['application_admitted'])
        before=len(self.server.requests)
        with self.assertRaisesRegex(RuntimeError,'withheld'):
            session.request('POST',self.config['origin']+'/v1/chat/completions',[('authorization','sentinel')],b'{}')
        self.assertEqual(len(self.server.requests),before)
        self.assertTrue(all(auth is None for _,auth in self.server.requests))
        return r

    def test_malformed_report_is_invalid_evidence(self):
        r=self.connect();self.assertEqual((r['status'],r['reason']),('invalid_evidence','malformed_report'))

    def test_oversized_report_is_rejected(self):
        self.server.length=4*1024*1024+1
        self.assertEqual(self.connect()['reason'],'input_too_large')

    def test_unsupported_wire_version_is_distinct(self):
        self.server.body=b'{"profile":"azure-snp-vtpm-ima/1","wireVersion":2}'
        r=self.connect();self.assertEqual((r['status'],r['reason']),('unsupported_profile','unsupported_wire_version'))

    def test_dependency_failure_is_distinct(self):
        self.server.status=503
        r=self.connect();self.assertEqual((r['status'],r['reason']),('dependency_unavailable','collection_unavailable'))

    def test_redirect_is_never_followed(self):
        with self.assertRaisesRegex(RuntimeError,'redirect'):
            confido.discover_py(json.dumps(self.config))
        self.assertEqual(self.server.requests,[('/service-info',None)])

    def test_cross_origin_advertisement_does_not_send_challenge(self):
        preview=json.loads(json.dumps(self.preview));preview['teeReport']['endpoint']='https://other.invalid/tee-report'
        self.assertEqual(self.connect(preview)['reason'],'unsupported_discovery')
        self.assertEqual(self.server.requests,[])

    def test_session_cannot_be_constructed_from_a_forged_result(self):
        with self.assertRaises(TypeError):confido.AttestedSession()


if __name__=='__main__':unittest.main()
