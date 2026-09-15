"""Write only the collector payload to a controller-owned evidence file."""
import json
import os
from ansible.plugins.callback import CallbackBase

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'baseline'
    CALLBACK_NEEDS_ENABLED = True

    def v2_runner_on_ok(self, result):
        if result._task.get_name() != 'Read Linux operating system and hardware state':
            return
        try:
            facts = json.loads(result._result.get('stdout', ''))
            if not isinstance(facts, dict): return
        except (ValueError, TypeError):
            return
        with open(os.environ['BASELINE_EVIDENCE_FILE'], 'a') as f:
            f.write(json.dumps({'host': result._host.get_name(), 'facts': facts}) + '\n')
