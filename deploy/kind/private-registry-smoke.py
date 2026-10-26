#!/usr/bin/env python3
# Isolated TLS OCI fixtures exercise admission and real pinned cosign; no kubelet runtime claim.
import json,subprocess,pathlib,time,concurrent.futures,threading
import os,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
os.chdir(ROOT)
E=pathlib.Path(os.environ.get("MODELGATE_EVIDENCE_DIR", "artifacts/private-kind")); E.mkdir(parents=True,exist_ok=True)
ctx=['kubectl']
def command(args,input=None):
 p=subprocess.run(args,input=input,text=True,capture_output=True)
 print(p.stdout,p.stderr,flush=True); p.check_returncode(); return p.stdout
cluster=os.environ.get('CLUSTER','modelgate')
command(['docker','build','-f','deploy/kind/registry-fixture.Dockerfile','-t','modelgate-registry-fixture:local','.'])
command(['kind','load','docker-image','modelgate-registry-fixture:local','--name',cluster])
command(ctx+['apply','-f','-'],json.dumps({'apiVersion':'v1','kind':'Namespace','metadata':{'name':'modelgate-system'}}))
command(ctx+['-n','modelgate-system','delete','pod','tls-registry-fixture','--ignore-not-found'])
command(ctx+['apply','-f','-'],json.dumps({'apiVersion':'v1','kind':'Pod','metadata':{'name':'tls-registry-fixture','namespace':'modelgate-system'},'spec':{'restartPolicy':'Never','containers':[{'name':'registry','image':'modelgate-registry-fixture:local','imagePullPolicy':'Never','resources':{'requests':{'cpu':'50m','memory':'64Mi'},'limits':{'cpu':'500m','memory':'256Mi'}},'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'readOnlyRootFilesystem':True,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'RuntimeDefault'}}}]}}))
command(ctx+['-n','modelgate-system','wait','--for=condition=Ready','pod/tls-registry-fixture','--timeout=90s'])
bootstrap=command(ctx+['-n','modelgate-system','logs','tls-registry-fixture'])
(E/'fixture-bootstrap.txt').write_text(bootstrap)
b=json.loads(next(x for x in bootstrap.splitlines() if x.startswith('REGISTRY_BOOTSTRAP='))[19:])
command(['docker','build','-t','modelgate-webhook:kind','.'])
command(['kind','load','docker-image','modelgate-webhook:kind','--name',cluster])
with tempfile.TemporaryDirectory() as d:
 policyfile=pathlib.Path(d)/'registry-policy.json';policyfile.write_text(json.dumps(b['registryPolicy']))
 env=os.environ.copy();env['REGISTRY_POLICY_FILE']=str(policyfile)
 p=subprocess.run([os.environ.get('BASH_BIN','bash'),'deploy/kind/deploy.sh'],env=env);p.check_returncode()
p={'apiVersion':'modelgate.dev/v1alpha1','kind':'ModelGatePolicy','metadata':{'name':'default-policy','namespace':'default'},'spec':{'cosignPublicKeyPEM':b['publicKey']}}
command(ctx+['apply','-f','-'],json.dumps(p))
results=[]
def run(obj,allowed,label):
 p=subprocess.run(ctx+['create','--dry-run=server','-f','-','-o','json'],input=json.dumps(obj),text=True,capture_output=True)
 ok=(p.returncode==0)==allowed and (allowed or 'denied the request' in p.stderr)
 results.append(dict(case=label,expectedAllowed=allowed,exit=p.returncode,passCheck=ok,output=p.stdout if p.returncode==0 else p.stderr))
 print(label, 'PASS' if ok else 'FAIL',p.stderr[:350],flush=True)
 return p
def pod(repo='signed',ns='default',**spec):
 return dict(apiVersion='v1',kind='Pod',metadata=dict(name='release-check',namespace=ns),spec=dict(containers=[dict(name='check',image=b['host']+'/'+repo+'@'+b['digest'])],**spec))

def wait_for_admission():
 # Deployment readiness can precede Service routing on a newly started cluster.
 # Retry only connection refusal, never an actual admission denial or TLS failure.
 deadline=time.monotonic()+30
 while True:
  p=subprocess.run(ctx+['create','--dry-run=server','--request-timeout=15s','-f','-','-o','json'],input=json.dumps(pod()),text=True,capture_output=True)
  if p.returncode==0:
   print('Admission startup round-trip ready',flush=True)
   return
  print(p.stderr,flush=True)
  if 'failed calling webhook' not in p.stderr or 'connection refused' not in p.stderr or time.monotonic()>=deadline:
   raise RuntimeError('Admission startup round-trip failed: '+p.stderr)
  time.sleep(1)

wait_for_admission()
for repo in ['signed','authenticated','unsigned','wrong-signature','wrong-artifact','wrong-repository','malformed-signature','bad-content','redirect-untrusted','redirect-private','redirect-loopback','auth-untrusted','slow-registry','partial-response','oversized-manifest','secret-error']:
 run(pod(repo),repo in ['signed','authenticated'],repo)
for host in ['127.0.0.1:443','169.254.169.254','100.100.100.200','unapproved.example']:
 o=pod();o['spec']['containers'][0]['image']=host+'/signed@'+b['digest'];run(o,False,'destination-'+host)
o=pod();o['spec']['containers'][0]['image']=b['host']+'/signed:latest';run(o,False,'mutable-tag')
for key in ['hostNetwork','hostPID','hostIPC']:run(pod(**{key:True}),False,key)
o=pod();o['spec']['containers'][0]['securityContext']={'privileged':True};run(o,False,'privileged')
run(pod(volumes=[dict(name='host',hostPath=dict(path='/'))]),False,'hostPath')
subprocess.run(ctx+['create','namespace','release-no-policy'],capture_output=True)
run(pod(ns='release-no-policy'),False,'missing-policy')
barrier=threading.Barrier(12)
def slow(i):
 barrier.wait();return run(pod('slow-registry'),False,'saturation-'+str(i))
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:list(pool.map(slow,range(12)))
results.append(dict(case='saturation-observed',passCheck=any('capacity' in r['output'] for r in results if r['case'].startswith('saturation-'))))
control=command(ctx+['-n','kube-system','get','pods','-o','json'])
controlPods=json.loads(control)['items']
results.append(dict(case='kube-system-status',passCheck=bool(controlPods) and all(x.get('status',{}).get('phase') in ['Running','Succeeded'] for x in controlPods)))
(E/'admission-results.json').write_text(json.dumps(results,indent=2))
raise SystemExit(0 if all(r['passCheck'] for r in results) else 1)
