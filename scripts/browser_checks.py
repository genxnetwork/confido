#!/usr/bin/env python3
"""Browser worker checks. Optional private hardware archive stays on localhost.
Without --bundle, checks API failures, CSP, worker startup and WASM imports.
With --bundle/--at, compares real evidence and negative mutations with Python.
"""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import shutil
import subprocess
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright, expect
import confido_verifier
from archive_inputs import migrate, arguments, encode
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path);p.add_argument('--at',type=int);args=p.parse_args()
policy=(ROOT/'profiles/verifier-match.json').read_bytes()
values=[b'',b'',b'',b'',policy,bytes(32),1750000000]
cases=[('missing_input',values)]
if args.bundle:
    if args.at is None:p.error('--bundle requires --at')
    archive=migrate(json.loads(args.bundle.read_text()),args.at)
    values=arguments(archive,policy);cases.append(('hardware',values))
    wrong=values.copy();wrong[5]=bytes(32);cases.append(('wrong_nonce',wrong))
    changed=values.copy();changed[3]+=b' ';cases.append(('reference_mutation',changed))
    bad=values.copy();report=json.loads(bad[0]);report['evidence']['quote']['signature'][0]^=1;bad[0]=json.dumps(report).encode();cases.append(('quote_mutation',bad))
    changed=values.copy();ref=json.loads(changed[3]);ref['ima_measurements'][1]['filedata_hash']='0'*64;changed[3]=json.dumps(ref).encode();pol=json.loads(policy);pol['reference']['sha256']=hashlib.sha256(changed[3]).hexdigest();changed[4]=json.dumps(pol).encode();cases.append(('ima_reference_mismatch',changed))
    changed=values.copy();ref=json.loads(changed[3]);ref['pcr10_sha256']='0'*64;changed[3]=json.dumps(ref).encode();pol=json.loads(policy);pol['reference']['sha256']=hashlib.sha256(changed[3]).hexdigest();changed[4]=json.dumps(pol).encode();cases.append(('pcr10_mismatch',changed))
cli=ROOT/'client/target/debug/confido_client'
metadata=json.loads(subprocess.check_output([str(cli),'--build-info']))
assert metadata['core']['source_sha256']==confido_verifier.build_info()['core']['source_sha256']
assert metadata['core']['pipeline_revision']==2
with tempfile.TemporaryDirectory() as directory:
    folder=Path(directory)
    for name, values in cases:
        expected=confido_verifier.verify(*values)
        record={'schema_version':2,'mode':'historical_replay',
                'inputs':{key:encode(value) for key,value in zip(('report','amd_chain','vcek','reference'),values[:4])},
                'context':{'expected_nonce_base64':encode(values[5]),'evaluation_unix_seconds':values[6]}}
        (folder/'archive.json').write_text(json.dumps(record));(folder/'policy.json').write_bytes(values[4])
        process=subprocess.run([str(cli),'replay',str(folder/'policy.json'),str(folder/'archive.json'),str(values[6])],capture_output=True,text=True)
        assert process.returncode==(0 if expected['status']=='verified' else 2),(name,process.stderr)
        assert json.loads(process.stdout)==expected,('cli',name)
print(f'CLI: {len(cases)} identical installed Python results')

class Handler(SimpleHTTPRequestHandler):
    def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(ROOT/'extension/dist/chromium')))
threading.Thread(target=server.serve_forever,daemon=True).start()
url=f'http://127.0.0.1:{server.server_port}/index.html'
try:
    with sync_playwright() as p:
        for browser_name in ('chromium','firefox'):
            browser=getattr(p,browser_name).launch(headless=True)
            page=browser.new_page();page.goto(url)
            metadata=page.evaluate('''() => new Promise((resolve,reject) => {const w=new Worker('./worker.js',{type:'module'});w.onmessage=({data})=>{w.terminate();data.error?reject(Error(data.error)):resolve(data.result);};w.postMessage({id:1,operation:'metadata',input:{}});})''')
            assert metadata['core']['pipeline_revision']==2
            assert metadata['core']['source_sha256']==confido_verifier.build_info()['core']['source_sha256']
            imports=page.evaluate('''async () => {const m=await WebAssembly.compile(await (await fetch('./wasm/confido_verifier_bg.wasm')).arrayBuffer());return WebAssembly.Module.imports(m).map(i=>i.name);}''')
            assert not any(x.lower() in str(imports).lower() for x in ('fetch','random','socket','date_now')),imports
            for name,values in cases:
                expected=confido_verifier.verify(*values)
                payload={k:encode(v) for k,v in zip(('report','amd_chain','vcek','reference','policy','nonce'),values[:6])};payload['at']=values[6]
                actual=page.evaluate('''input => new Promise((resolve,reject) => {
                  const w=new Worker('./worker.js',{type:'module'});
                  const timer=setTimeout(()=>{w.terminate();reject(Error('timeout'));},30000);
                  w.onerror=e=>{clearTimeout(timer);w.terminate();reject(Error(e.message));};
                  w.onmessage=({data})=>{clearTimeout(timer);w.terminate();data.error?reject(Error(data.error)):resolve(data.result);};
                  for(const k of ['report','amd_chain','vcek','reference','policy','nonce']) input[k]=Uint8Array.from(atob(input[k]),c=>c.charCodeAt(0));
                  w.postMessage({id:1,operation:'verify',input});
                })''',payload)
                assert actual==expected,(browser_name,name)
            print(browser_name+': '+str(len(cases))+' identical Python/WASM results; no network/RNG/clock WASM imports')
            browser.close()
        # Real MV3 extension origin and CSP, independent of the localhost harness.
        with tempfile.TemporaryDirectory() as profile:
            extension=ROOT/'extension/dist/chromium'
            ctx=p.chromium.launch_persistent_context(profile,channel='chromium',headless=True,args=[f'--disable-extensions-except={extension}',f'--load-extension={extension}'])
            worker=ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event('serviceworker')
            page=ctx.new_page();page.goto('chrome-extension://'+worker.url.split('/')[2]+'/index.html')
            page.locator('#policy').set_input_files(ROOT/'profiles/verifier-match.json')
            empty={'schema_version':2,'inputs':{k:'' for k in ('report','amd_chain','vcek','reference')},'context':{'expected_nonce_base64':encode(bytes(32))}}
            page.locator('#archive').set_input_files({'name':'input.json','mimeType':'application/json','buffer':json.dumps(empty).encode()})
            page.locator('#time').fill('1750000000');page.locator('#replay').click()
            expect(page.locator("#status")).to_contain_text("incomplete_input", timeout=30000)
            assert not page.locator('#save').is_disabled()
            ctx.close();print('Chromium installed MV3 extension: worker, CSP and local replay passed')
        # A stale caller asset or WASM/source identity must fail before any evidence call.
        for mismatch in ('asset', 'core_identity'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory); ext=root/'extension';shutil.copytree(ROOT/'extension/dist/chromium',ext)
                if mismatch=='asset':
                    with (ext/'collection.js').open('a') as f:f.write('\n// deliberately stale asset\n')
                else:
                    manifest=json.loads((ext/'runtime-manifest.json').read_text());manifest['core_source_sha256']='0'*64
                    (ext/'runtime-manifest.json').write_text(json.dumps(manifest))
                ctx=p.chromium.launch_persistent_context(root/'profile',channel='chromium',headless=True,args=[f'--disable-extensions-except={ext}',f'--load-extension={ext}'])
                worker=ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event('serviceworker')
                page=ctx.new_page();page.goto('chrome-extension://'+worker.url.split('/')[2]+'/index.html')
                page.locator('#replay').click()
                expect(page.locator('#status')).to_contain_text('diff',timeout=30000)
                assert page.locator('#save').is_disabled()
                ctx.close()
        print('Chromium rejects mixed JS/WASM assets and mismatched embedded source identity')
finally:server.shutdown()
