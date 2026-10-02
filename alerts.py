"""Step 5b: explainable alert generation (console + file + DB)."""
import datetime
import config


def raise_alert(storage, ev, f, v, action):
    when = datetime.datetime.fromtimestamp(ev.ts).isoformat(timespec="seconds")
    msg = (f"[ALERT] {when} src={ev.src_ip} domain={f.parent} fqdn={ev.fqdn[:80]} "
           f"score={v.score} action={action} why=" + "; ".join(v.reasons))
    print(msg)
    with open(config.LOG_PATH, "a") as fh:
        fh.write(msg + "\n")
    storage.log_alert(ev.ts, ev.src_ip, f.parent, v.score, v.reasons, action)
