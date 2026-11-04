import csv, os, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
MODES = ("static", "dynamic")
LEVELS = [1, 10, 50, 100]

data = {}
for m in MODES:
    with open(os.path.join(R, "results_%s.csv" % m)) as f:
        for r in csv.DictReader(f):
            data.setdefault((m, r["condition"], r["metric"]), []).append(float(r["value"]))


def avg(m, cond, metric):
    vals = [v for v in data[(m, cond, metric)] if v == v]     # drop NaN
    return statistics.mean(vals) if vals else float("nan")


def bars(ax, labels, series, title, ylabel):
    w = 0.38
    for i, m in enumerate(MODES):
        ax.bar([x + (i - 0.5) * w for x in range(len(labels))], series[m], w, label=m)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.legend()


lv = [str(c) for c in LEVELS]
fig, axs = plt.subplots(2, 3, figsize=(16, 9))

for ax, metric, title, ylabel in [
    (axs[0][0], "req_per_sec", "Request rate vs concurrency", "requests/sec"),
    (axs[0][1], "ms_per_request", "Mean time per request vs concurrency", "ms"),
    (axs[0][2], "flow_entries", "Flow-table entries after test", "entries"),
]:
    series = {m: [avg(m, "concurrency_%d" % c, metric) for c in LEVELS] for m in MODES}
    bars(ax, lv, series, title, ylabel)
    ax.set_xlabel("concurrent clients (ab -c)")

bars(axs[1][0], ["1 stream", "4 streams"],
     {m: [avg(m, "throughput", "mbps_1stream"), avg(m, "throughput", "mbps_4stream")] for m in MODES},
     "TCP throughput (iperf3)", "Mbit/s")
bars(axs[1][1], ["first connection", "repeat connection"],
     {m: [avg(m, "latency", "connect_cold_ms"), avg(m, "latency", "connect_warm_ms")] for m in MODES},
     "TCP connection set-up time", "ms")
bars(axs[1][2], ["no attack", "under attack"],
     {m: [avg(m, "concurrency_50", "req_per_sec"), avg(m, "attack", "req_per_sec")] for m in MODES},
     "Alice's request rate (50 clients)", "requests/sec")

fig.tight_layout()
out = os.path.join(R, "performance.png")
fig.savefig(out, dpi=150)

print("\n%-40s %12s %12s" % ("condition / metric", "static", "dynamic"))
for cond, metric in sorted({(k[1], k[2]) for k in data}):
    print("%-40s %12.2f %12.2f" % (cond + " / " + metric,
                                   avg("static", cond, metric), avg("dynamic", cond, metric)))
print("\nSaved", out)
