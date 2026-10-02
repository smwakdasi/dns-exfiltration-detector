"""Glue: event -> features -> verdict -> log -> (alert + mitigation)."""
from alerts import raise_alert
from detector import evaluate
from features import FeatureExtractor
from mitigation import Mitigator
from storage import Storage


class Pipeline:
    def __init__(self, enforce=False, db_path=None):
        self.storage = Storage(db_path) if db_path else Storage()
        self.fx = FeatureExtractor()
        self.mit = Mitigator(self.storage, enforce=enforce)

    def process(self, ev):
        f = self.fx.extract(ev)
        v = evaluate(f)
        self.storage.log_query(ev, f, v)
        if v.suspicious:
            action = self.mit.mitigate(ev.ts, ev.src_ip, f.parent)
            if action not in ("already-blocked",):
                raise_alert(self.storage, ev, f, v, action)
        self.mit.expire(ev.ts)
        return f, v
