#!/usr/bin/env python3
"""
MoFA Cognitive Gateway - research-grade chart generator
saves one PNG per chart into gsoc/mofa_assets/ at 300 DPI

usage:
  python3 scripts/gateway-charts.py
  python3 scripts/gateway-charts.py --duration 60
  python3 scripts/gateway-charts.py --out /some/other/folder
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker
from matplotlib.colors import LinearSegmentedColormap
import numpy as np
import seaborn as sns

BASE  = "http://127.0.0.1:8080"
ADMIN = "admin-secret-2025"
HZ    = 2

# ── palette ───────────────────────────────────────────────────────────────────
C = {
    "red":    "#C0392B",
    "blue":   "#2471A3",
    "yellow": "#D4AC0D",
    "teal":   "#148F77",
    "coral":  "#E8674A",
    "purple": "#6C3483",
    "gray":   "#707B7C",
    "dark":   "#1C2833",
    "light":  "#F2F3F4",
    "white":  "#FFFFFF",
}
PALETTE = [C["blue"], C["red"], C["teal"], C["yellow"],
           C["coral"], C["purple"], C["gray"]]

# ── global matplotlib style ───────────────────────────────────────────────────
plt.rcParams.update({
    "font.family":        "DejaVu Sans",
    "font.size":          9,
    "axes.titlesize":     11,
    "axes.titleweight":   "bold",
    "axes.labelsize":     9,
    "axes.labelcolor":    C["dark"],
    "axes.titlecolor":    C["dark"],
    "axes.spines.top":    False,
    "axes.spines.right":  False,
    "axes.spines.left":   True,
    "axes.spines.bottom": True,
    "axes.edgecolor":     "#BDC3C7",
    "axes.linewidth":     0.8,
    "axes.facecolor":     C["white"],
    "figure.facecolor":   C["white"],
    "grid.color":         "#ECF0F1",
    "grid.linewidth":     0.6,
    "xtick.color":        "#5D6D7E",
    "ytick.color":        "#5D6D7E",
    "xtick.major.size":   3,
    "ytick.major.size":   3,
    "legend.framealpha":  0.9,
    "legend.edgecolor":   "#BDC3C7",
    "legend.fontsize":    8,
    "savefig.dpi":        300,
    "savefig.bbox":       "tight",
    "savefig.facecolor":  C["white"],
})

DPI    = 300
SUFFIX = ".png"


# ── data collection ───────────────────────────────────────────────────────────

def fetch(path, admin=False):
    h = {"content-type": "application/json"}
    if admin:
        h["x-admin-key"] = ADMIN
    req = urllib.request.Request(f"{BASE}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())
    except Exception:
        return None


def collect(duration):
    steps    = max(1, int(duration * HZ))
    interval = 1.0 / HZ
    snaps    = []
    print(f"collecting {duration}s at {HZ} Hz ({steps} samples)...")
    for i in range(steps):
        t0 = time.time()
        m  = fetch("/live/metrics")
        if m is None:
            print("\ngateway not responding on :8080")
            sys.exit(1)
        if i % HZ == 0:
            m["_plugins"] = fetch("/admin/plugins", admin=True) or []
            m["_routes"]  = fetch("/admin/routes",  admin=True) or []
        m["_t"] = time.time()
        snaps.append(m)
        wait = interval - (time.time() - t0)
        if wait > 0 and i < steps - 1:
            time.sleep(wait)
        done = int((i + 1) / steps * 50)
        print(f"\r  [{'█'*done}{'░'*(50-done)}] {i+1}/{steps}", end="", flush=True)
    print()
    return snaps


def deltas(series):
    return [0] + [max(0, series[i] - series[i-1]) for i in range(1, len(series))]


def save(fig, folder, name):
    path = folder / f"{name}{SUFFIX}"
    fig.savefig(path, dpi=DPI)
    plt.close(fig)
    print(f"  saved  {path.name}")
    return path


# ── chart 01: request rate time series ───────────────────────────────────────

def chart_request_rate(snaps, folder):
    ts   = [s["_t"] - snaps[0]["_t"] for s in snaps]
    keys = [
        ("total",         "Total",         C["dark"],   "-",  0.08),
        ("routed",        "Routed (2xx)",   C["blue"],   "-",  0.15),
        ("rate_limited",  "Rate-limited (429)", C["yellow"], "--", 0.12),
        ("auth_rejected", "Auth rejected (401)", C["red"],  ":",  0.10),
    ]

    fig, ax = plt.subplots(figsize=(7, 3.2))

    for key, label, color, ls, alpha in keys:
        vals = deltas([s.get(key, 0) for s in snaps])
        ax.fill_between(ts, vals, alpha=alpha, color=color)
        ax.plot(ts, vals, color=color, lw=1.6, linestyle=ls, label=label)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Requests / sample")
    ax.set_title("Request Rate Over Time")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=5))
    ax.set_xlim(left=0)
    ax.legend(loc="upper right", ncol=2)
    ax.grid(True, axis="y")

    fig.tight_layout()
    return save(fig, folder, "01_request_rate")


# ── chart 02: agent distribution ─────────────────────────────────────────────

def chart_agent_distribution(snaps, folder):
    last   = next((s for s in reversed(snaps) if s.get("agents")), snaps[-1])
    agents = last.get("agents", {})
    if not agents:
        agents = {"no data": 1}

    names  = sorted(agents, key=lambda k: agents[k])  # ascending for barh
    counts = [agents[n] for n in names]
    total  = sum(counts)
    pcts   = [c / total * 100 for c in counts]

    fig, ax = plt.subplots(figsize=(6.5, max(2.5, 0.45 * len(names) + 1.2)))

    colors = [PALETTE[i % len(PALETTE)] for i in range(len(names))]
    bars   = ax.barh(names, counts, color=colors, edgecolor="white",
                     linewidth=0.8, height=0.6)

    for bar, count, pct in zip(bars, counts, pcts):
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                f"{count}  ({pct:.1f}%)",
                va="center", ha="left", fontsize=8, color=C["dark"])

    ax.set_xlabel("Requests Handled")
    ax.set_title("Agent Routing Distribution")
    ax.set_xlim(right=max(counts) * 1.35)
    ax.grid(True, axis="x")
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)

    fig.tight_layout()
    return save(fig, folder, "02_agent_distribution")


# ── chart 03: status code breakdown ──────────────────────────────────────────

def chart_status(snaps, folder):
    counts = defaultdict(int)
    for s in snaps:
        for r in s.get("recent", []):
            counts[r.get("status", 200)] += 1
    if not counts:
        last = snaps[-1]
        counts[200] = last.get("routed", 1)
        counts[429] = last.get("rate_limited", 0)
        counts[401] = last.get("auth_rejected", 0)
    counts = {k: v for k, v in counts.items() if v > 0}

    def color_for(code):
        if 200 <= code < 300: return C["blue"]
        if code == 429:        return C["yellow"]
        if code == 401:        return C["red"]
        return C["gray"]

    codes  = sorted(counts)
    vals   = [counts[c] for c in codes]
    colors = [color_for(c) for c in codes]
    total  = sum(vals)

    fig, ax = plt.subplots(figsize=(4.5, 4.5))

    wedges, texts, autotexts = ax.pie(
        vals,
        labels=[str(c) for c in codes],
        colors=colors,
        autopct=lambda p: f"{p:.1f}%\n({int(round(p*total/100))})",
        startangle=90,
        wedgeprops=dict(edgecolor=C["white"], linewidth=2),
        pctdistance=0.72,
        labeldistance=1.12,
    )
    for t in texts:
        t.set_fontsize(9)
        t.set_color(C["dark"])
    for at in autotexts:
        at.set_fontsize(7.5)
        at.set_color(C["white"])
        at.set_fontweight("bold")

    # donut hole
    centre = plt.Circle((0, 0), 0.48, color=C["white"])
    ax.add_patch(centre)
    ax.text(0, 0.08, str(total), ha="center", va="center",
            fontsize=14, fontweight="bold", color=C["dark"])
    ax.text(0, -0.18, "total req", ha="center", va="center",
            fontsize=8, color=C["gray"])

    ax.set_title("Status Code Breakdown")
    fig.tight_layout()
    return save(fig, folder, "03_status_breakdown")


# ── chart 04: cache performance ───────────────────────────────────────────────

def chart_cache(snaps, folder):
    ts       = [s["_t"] - snaps[0]["_t"] for s in snaps]
    hit_rate = [s.get("cache", {}).get("hit_rate_pct", 0) for s in snaps]
    hits_ts  = deltas([s.get("cache", {}).get("hits",   0) for s in snaps])
    miss_ts  = deltas([s.get("cache", {}).get("misses", 0) for s in snaps])
    size_ts  = [s.get("cache", {}).get("size", 0) for s in snaps]

    fig, axes = plt.subplots(1, 2, figsize=(9, 3.2))

    # left: hit rate + size
    ax = axes[0]
    ax.fill_between(ts, hit_rate, alpha=0.15, color=C["blue"])
    ax.plot(ts, hit_rate, color=C["blue"], lw=2, label="Hit rate (%)")
    ax.axhline(50, color=C["gray"], lw=0.8, linestyle=":", alpha=0.7)
    ax.set_ylim(-5, 108)
    ax.set_ylabel("Cache Hit Rate (%)")
    ax.set_xlabel("Time (s)")
    ax.set_title("Hit Rate over Time")
    ax.grid(True, axis="y")

    ax2 = ax.twinx()
    ax2.plot(ts, size_ts, color=C["teal"], lw=1.2, linestyle="--", alpha=0.8, label="Entries")
    ax2.set_ylabel("Entries", color=C["teal"])
    ax2.tick_params(axis="y", colors=C["teal"], labelsize=8)
    ax2.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=4))
    ax2.spines["right"].set_edgecolor(C["teal"])

    h1 = mpatches.Patch(color=C["blue"], alpha=0.7, label="Hit rate %")
    h2 = mpatches.Patch(color=C["teal"], alpha=0.7, label="Entries")
    ax.legend(handles=[h1, h2], loc="lower right")

    # right: stacked area hits/misses
    ax = axes[1]
    ax.stackplot(ts, [hits_ts, miss_ts],
                 labels=["Hits", "Misses"],
                 colors=[C["blue"], C["gray"]],
                 alpha=0.75)
    ax.set_ylabel("Count / Sample")
    ax.set_xlabel("Time (s)")
    ax.set_title("Hits vs. Misses (Rate)")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=5))
    ax.legend(loc="upper right")
    ax.grid(True, axis="y")

    fig.tight_layout(w_pad=3)
    return save(fig, folder, "04_cache_performance")


# ── chart 05: latency heatmap ─────────────────────────────────────────────────

def chart_latency_heatmap(snaps, folder):
    all_recent = []
    seen = set()
    for s in snaps:
        for r in s.get("recent", []):
            k = r.get("ts_ms")
            if k not in seen:
                seen.add(k)
                all_recent.append(r)

    if not all_recent:
        fig, ax = plt.subplots(figsize=(7, 2))
        ax.text(0.5, 0.5, "No request data collected",
                ha="center", va="center", color=C["gray"], transform=ax.transAxes)
        ax.set_title("Latency Heatmap (ms)")
        fig.tight_layout()
        return save(fig, folder, "05_latency_heatmap")

    paths     = sorted(set(r["path"] for r in all_recent))
    t0        = snaps[0]["_t"]
    duration  = snaps[-1]["_t"] - t0
    bucket_s  = max(1, duration / 12)
    n_buckets = max(2, int(duration / bucket_s) + 1)

    hm = np.full((len(paths), n_buckets), np.nan)
    for r in all_recent:
        t  = r.get("ts_ms", 0) / 1000
        b  = int((t - t0) / bucket_s)
        if b < 0 or b >= n_buckets:
            continue
        pi  = paths.index(r["path"])
        lat = r.get("latency_ms", 0)
        hm[pi, b] = lat if np.isnan(hm[pi, b]) else (hm[pi, b] + lat) / 2

    cmap = LinearSegmentedColormap.from_list(
        "mofa", ["#EBF5FB", "#5DADE2", "#1A5276", "#C0392B"])

    fig_h = max(2.5, 0.55 * len(paths) + 1.2)
    fig, ax = plt.subplots(figsize=(10, fig_h))

    x_labels = [f"+{int(b * bucket_s)}s" for b in range(n_buckets)]
    y_labels  = [p.replace("/v1/invoke/", "/") for p in paths]

    sns.heatmap(
        hm,
        ax=ax,
        cmap=cmap,
        annot=True,
        fmt=".0f",
        linewidths=0.4,
        linecolor="#ECF0F1",
        xticklabels=x_labels,
        yticklabels=y_labels,
        cbar_kws=dict(label="Avg latency (ms)", shrink=0.85, pad=0.02),
        annot_kws=dict(fontsize=8),
        mask=np.isnan(hm),
    )
    ax.set_title("Request Latency Heatmap — Paths × Time Buckets (ms)")
    ax.set_xlabel("Time bucket")
    ax.set_ylabel("Route path")
    ax.tick_params(axis="both", labelsize=8)

    fig.tight_layout()
    return save(fig, folder, "05_latency_heatmap")


# ── chart 06: latency scatter ─────────────────────────────────────────────────

def chart_latency_scatter(snaps, folder):
    all_recent = []
    seen = set()
    for s in snaps:
        for r in s.get("recent", []):
            k = r.get("ts_ms")
            if k not in seen:
                seen.add(k)
                all_recent.append(r)

    fig, ax = plt.subplots(figsize=(8, 3.5))

    if not all_recent:
        ax.text(0.5, 0.5, "No data", ha="center", va="center",
                color=C["gray"], transform=ax.transAxes)
    else:
        t0       = snaps[0]["_t"]
        by_agent = defaultdict(list)
        for r in all_recent:
            by_agent[r.get("agent", "?")].append(r)

        agent_col = {a: PALETTE[i % len(PALETTE)]
                     for i, a in enumerate(sorted(by_agent))}

        for agent, reqs in sorted(by_agent.items()):
            xs  = [r.get("ts_ms", 0) / 1000 - t0 for r in reqs]
            ys  = [r.get("latency_ms", 0)          for r in reqs]
            ok  = [(x, y) for x, y, r in zip(xs, ys, reqs) if r.get("status", 200) < 400]
            bad = [(x, y) for x, y, r in zip(xs, ys, reqs) if r.get("status", 200) >= 400]

            color = agent_col[agent]
            if ok:
                ax.scatter([p[0] for p in ok], [p[1] for p in ok],
                           color=color, s=22, alpha=0.8,
                           label=agent, edgecolors="none", zorder=3)
            if bad:
                ax.scatter([p[0] for p in bad], [p[1] for p in bad],
                           color=color, s=45, alpha=0.9, marker="X",
                           edgecolors=C["dark"], linewidths=0.5, zorder=4,
                           label=f"{agent} (error)")

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Per-Request Latency Scatter (● = 2xx, ✕ = error)")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.set_xlim(left=0)
    if all_recent:
        ax.legend(loc="upper right", ncol=2, markerscale=1.2)

    fig.tight_layout()
    return save(fig, folder, "06_latency_scatter")


# ── chart 07: latency boxplot per path ────────────────────────────────────────

def chart_latency_boxplot(snaps, folder):
    all_recent = []
    seen = set()
    for s in snaps:
        for r in s.get("recent", []):
            k = r.get("ts_ms")
            if k not in seen:
                seen.add(k)
                all_recent.append(r)

    fig, ax = plt.subplots(figsize=(7, max(2.8, 0.5 * 5 + 1.2)))

    if not all_recent:
        ax.text(0.5, 0.5, "No data", ha="center", va="center",
                color=C["gray"], transform=ax.transAxes)
    else:
        by_path = defaultdict(list)
        for r in all_recent:
            by_path[r["path"]].append(r.get("latency_ms", 0))

        paths_s = sorted(by_path, key=lambda p: np.median(by_path[p]))
        data    = [by_path[p] for p in paths_s]
        labels  = [p.replace("/v1/invoke/", "/") for p in paths_s]

        bp = ax.boxplot(
            data, vert=False, patch_artist=True,
            widths=0.5, notch=False,
            boxprops=dict(linewidth=1.1),
            medianprops=dict(color=C["white"], linewidth=2.5),
            whiskerprops=dict(linewidth=1, linestyle="--", color=C["gray"]),
            capprops=dict(linewidth=1.2, color=C["gray"]),
            flierprops=dict(marker=".", color=C["red"], markersize=4, alpha=0.5),
        )
        for patch, color in zip(bp["boxes"], PALETTE):
            patch.set_facecolor(color)
            patch.set_alpha(0.72)

        ax.set_yticks(range(1, len(labels) + 1))
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlabel("Latency (ms)")
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)

    ax.set_title("Latency Distribution per Route (Boxplot)")
    ax.grid(True, axis="x", linestyle="--", alpha=0.5)
    fig.tight_layout()
    return save(fig, folder, "07_latency_boxplot")


# ── chart 08: MQTT activity ───────────────────────────────────────────────────

def chart_mqtt(snaps, folder):
    ts     = [s["_t"] - snaps[0]["_t"] for s in snaps]
    d_pub  = deltas([s.get("mqtt", {}).get("published", 0) for s in snaps])
    d_recv = deltas([s.get("mqtt", {}).get("received",  0) for s in snaps])
    devs   = snaps[-1].get("mqtt", {}).get("devices", 0)
    pub_total  = snaps[-1].get("mqtt", {}).get("published", 0)
    recv_total = snaps[-1].get("mqtt", {}).get("received",  0)

    fig, ax = plt.subplots(figsize=(7, 3))

    ax.fill_between(ts, d_pub,  alpha=0.18, color=C["teal"])
    ax.plot(ts, d_pub,  color=C["teal"],  lw=2, label=f"Published  (total: {pub_total})")
    ax.fill_between(ts, d_recv, alpha=0.18, color=C["coral"])
    ax.plot(ts, d_recv, color=C["coral"], lw=1.8, linestyle="--",
            label=f"Received   (total: {recv_total})")

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Messages / sample")
    ax.set_title(f"MQTT IoT Message Rate  ({devs} devices registered)")
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=5))
    ax.set_xlim(left=0)
    ax.legend()
    ax.grid(True, axis="y")

    fig.tight_layout()
    return save(fig, folder, "08_mqtt_activity")


# ── chart 09: plugin registry ─────────────────────────────────────────────────

def chart_plugins(snaps, folder):
    last    = next((s for s in reversed(snaps) if s.get("_plugins")), snaps[-1])
    plugins = last.get("_plugins", [])

    fig, axes = plt.subplots(1, 2, figsize=(10, max(2.8, 0.55 * max(len(plugins), 1) + 1.8)))

    # left: verified vs unsigned bar
    ax = axes[0]
    if plugins:
        names    = [p.get("name", "?")[:22] for p in plugins]
        verified = [1 if p.get("verified") else 0 for p in plugins]
        bar_colors = [C["blue"] if v else C["gray"] for v in verified]
        bars = ax.barh(names, [1] * len(names), color=bar_colors,
                       edgecolor="white", linewidth=1, height=0.5)
        for bar, p in zip(bars, plugins):
            label = f"v{p.get('version','?')}  {'✓ verified' if p.get('verified') else '⚠ unsigned'}"
            ax.text(0.04, bar.get_y() + bar.get_height() / 2,
                    label, va="center", ha="left", fontsize=8.5,
                    color=C["white"] if p.get("verified") else C["dark"])
        ax.set_xlim(0, 1.5)
        ax.set_xticks([])
        ax.invert_yaxis()
        ax.spines["bottom"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)
    else:
        ax.text(0.5, 0.5, "No plugins registered",
                ha="center", va="center", color=C["gray"], transform=ax.transAxes)
    ax.set_title("Plugin Verification Status")

    # right: capability frequency across plugins
    ax = axes[1]
    cap_count = defaultdict(int)
    for p in plugins:
        for c in p.get("capabilities", []):
            cap_count[c] += 1

    if cap_count:
        caps   = sorted(cap_count, key=lambda k: -cap_count[k])
        counts = [cap_count[c] for c in caps]
        y_pos  = range(len(caps))
        ax.barh(list(y_pos), counts, color=C["teal"], alpha=0.75,
                edgecolor="white", linewidth=0.8, height=0.5)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(caps, fontsize=8.5)
        ax.invert_yaxis()
        ax.set_xlabel("Plugin count")
        ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        ax.grid(True, axis="x", alpha=0.5)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)
    else:
        ax.text(0.5, 0.5, "No capabilities data",
                ha="center", va="center", color=C["gray"], transform=ax.transAxes)
    ax.set_title("Capability Coverage")

    fig.suptitle("Plugin Registry", fontsize=11, fontweight="bold", y=1.01)
    fig.tight_layout(w_pad=3)
    return save(fig, folder, "09_plugin_registry")


# ── chart 10: cumulative counters ─────────────────────────────────────────────

def chart_cumulative(snaps, folder):
    ts   = [s["_t"] - snaps[0]["_t"] for s in snaps]
    keys = [
        ("total",         "Total",              C["dark"],   "-"),
        ("routed",        "Routed (2xx)",         C["blue"],   "-"),
        ("rate_limited",  "Rate-limited (429)",   C["yellow"], "--"),
        ("auth_rejected", "Auth rejected (401)",  C["red"],    ":"),
    ]

    fig, ax = plt.subplots(figsize=(7, 3.2))

    for key, label, color, ls in keys:
        vals = [s.get(key, 0) for s in snaps]
        ax.plot(ts, vals, color=color, lw=1.8, linestyle=ls, label=label)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Cumulative Requests")
    ax.set_title("Cumulative Request Counters")
    ax.set_xlim(left=0)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(loc="upper left", ncol=2)
    ax.grid(True, axis="y")

    fig.tight_layout()
    return save(fig, folder, "10_cumulative_counters")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--duration", type=int, default=30,
                   help="seconds to collect (default 30)")
    p.add_argument("--out", default=None,
                   help="output folder (default: ~/gsoc/mofa_assets)")
    args = p.parse_args()

    folder = Path(args.out) if args.out else Path.home() / "gsoc" / "mofa_assets"
    folder.mkdir(parents=True, exist_ok=True)

    snaps = collect(max(1, args.duration))

    print(f"\ngenerating charts into {folder}/")
    chart_request_rate(snaps, folder)
    chart_agent_distribution(snaps, folder)
    chart_status(snaps, folder)
    chart_cache(snaps, folder)
    chart_latency_heatmap(snaps, folder)
    chart_latency_scatter(snaps, folder)
    chart_latency_boxplot(snaps, folder)
    chart_mqtt(snaps, folder)
    chart_plugins(snaps, folder)
    chart_cumulative(snaps, folder)

    print(f"\ndone — 10 charts saved to {folder}")
    try:
        import subprocess
        subprocess.Popen(["open", str(folder)])
    except Exception:
        pass


if __name__ == "__main__":
    main()
