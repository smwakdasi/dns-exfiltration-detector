"""Step 9: measure the Chapter-3 metrics on labelled traffic (no root/scapy needed).  python3 evaluate.py"""
import os
import time
import gen_traffic
from pipeline import Pipeline

DB = "eval.db"
if os.path.exists(DB):
    os.remove(DB)
p = Pipeline(enforce=False, db_path=DB)
tp = fp = tn = fn = 0
first_tunnel_ts = first_detect_ts = None
lat = []
for ev, is_tunnel in gen_traffic.mixed():
    s = time.perf_counter()
    _, v = p.process(ev)
    lat.append((time.perf_counter() - s) * 1000)
    if is_tunnel and first_tunnel_ts is None:
        first_tunnel_ts = ev.ts
    if is_tunnel and v.suspicious and first_detect_ts is None:
        first_detect_ts = ev.ts
    tp += is_tunnel and v.suspicious
    fn += is_tunnel and not v.suspicious
    fp += (not is_tunnel) and v.suspicious
    tn += (not is_tunnel) and not v.suspicious

print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
print(f"Detection rate (recall): {tp/(tp+fn):.1%}   False-positive rate: {fp/(fp+tn):.1%}   "
      f"False-negative rate: {fn/(tp+fn):.1%}   Accuracy: {(tp+tn)/(tp+tn+fp+fn):.1%}")
print(f"Time-to-first-detection (traffic time): {first_detect_ts-first_tunnel_ts:.1f}s | "
      f"avg per-query processing: {sum(lat)/len(lat):.3f} ms")
print(f"Domains blocked (dry-run): {[k[1] for k in p.mit.blocked]}")
