"""Read official public sources and record retrieval/parser outcomes (no host access)."""
import concurrent.futures
import json
from pathlib import Path
import time
from baseline.vendors import refresh

def check(source):
    try:
        result=refresh(source)
        return {'source':source,'status':result['status'],'retrieved_at':result['retrieved_at'],'sha256':result['sha256'],'candidate_count':len(result['candidates']),'sample':result['candidates'][:2]}
    except Exception as exc:return {'source':source,'status':'unavailable','checked_at':time.time(),'error':type(exc).__name__+': '+str(exc)[:200]}

if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(check,['rocky','rhel','centos','dell','hpe','ibm']))
    Path('docs/vendor-retrieval.json').write_text(json.dumps(results,indent=2)+'\n')
    for item in results:print(item['source'],item['status'],item.get('candidate_count',0),item.get('error',''))
