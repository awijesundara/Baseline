"""Write only the collector/job payload to a controller-owned evidence file."""
import json
import os
from ansible.plugins.callback import CallbackBase

COLLECTOR_TASKS = {'Read Linux operating system and hardware state', 'Read Windows operating system and hardware state'}
JOB_TASKS = {'Plan OS package upgrade', 'Apply OS package upgrade', 'Roll back OS package upgrade'}

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'baseline'
    CALLBACK_NEEDS_ENABLED = True

    def v2_runner_on_ok(self, result):
        name = result._task.get_name()
        if name in COLLECTOR_TASKS: key = 'facts'
        elif name in JOB_TASKS: key = 'result'
        else: return
        try:
            payload = json.loads(result._result.get('stdout', ''))
            if not isinstance(payload, dict): return
        except (ValueError, TypeError):
            return
        with open(os.environ['BASELINE_EVIDENCE_FILE'], 'a') as f:
            f.write(json.dumps({'host': result._host.get_name(), key: payload}) + '\n')
