"""Size and latency measurements required by WP4.

For an increasing number of disclosed claims it measures:

* credential (VC) size as stored in the wallet, presentation (VP) size, and
  the size of the encrypted VP actually sent to the verifier;
* wallet time to build and sign the presentation;
* verifier time to run checks 7.A-7.F (median and interquartile range).

Sizes are ``len()`` of the canonical UTF-8 JSON encoding (the first version
used ``sys.getsizeof``, which adds the Python object overhead).

Usage::

    python -m benchmarks.benchmark [--runs 50] [--out benchmarks/results]
"""

from __future__ import annotations

import argparse
import csv
import logging
import platform
import statistics
import time
from pathlib import Path

from credential_sharing.encoding import canonical_json
from credential_sharing.sample_data import DEMO_STUDENT_PASSWORD
from credential_sharing.scenario import build_system, sample_record

COLUMNS = [
    "disclosed_claims", "vc_bytes", "vp_bytes", "sealed_vp_bytes",
    "create_vp_ms_median", "verify_ms_median", "verify_ms_p25", "verify_ms_p75",
]


def measure(runs: int) -> list[dict[str, float]]:
    system = build_system()
    student = system.new_student(sample_record())
    start = time.perf_counter()
    student.obtain_credential(system.issuer, DEMO_STUDENT_PASSWORD, system.otp_reader(student))
    print(f"Issuance (login + DID binding + issue + wallet checks): {(time.perf_counter() - start) * 1000:.1f} ms")

    wallet, verifier = student.wallet, system.verifier
    vc_bytes = len(canonical_json(wallet.credentials[0]))
    claim_names = [name for name, _ in wallet.disclosable_claims()]
    # Courses first: they are what a verifier typically asks for.
    claim_names.sort(key=lambda name: "Courses" not in name)

    rows = []
    for count in sorted({1, 2, 3, 4, 6, 9, 12, len(claim_names)}):
        chosen = claim_names[:count]
        create_times, verify_times = [], []
        for _ in range(runs):
            request = verifier.create_presentation_request(chosen)
            t0 = time.perf_counter()
            presentation = wallet.create_presentation(request, chosen)
            t1 = time.perf_counter()
            report = verifier.verify_presentation(presentation)
            t2 = time.perf_counter()
            if not report.valid:
                raise RuntimeError(f"verification failed: {report.failure}")
            create_times.append((t1 - t0) * 1000)
            verify_times.append((t2 - t1) * 1000)
        request = verifier.create_presentation_request(chosen)
        presentation = wallet.create_presentation(request, chosen)
        quartiles = statistics.quantiles(verify_times, n=4)
        rows.append({
            "disclosed_claims": count,
            "vc_bytes": vc_bytes,
            "vp_bytes": len(canonical_json(presentation)),
            "sealed_vp_bytes": wallet.send_presentation(presentation, verifier.did).size,
            "create_vp_ms_median": round(statistics.median(create_times), 3),
            "verify_ms_median": round(statistics.median(verify_times), 3),
            "verify_ms_p25": round(quartiles[0], 3),
            "verify_ms_p75": round(quartiles[2], 3),
        })
    return rows


def write_csv(rows: list[dict[str, float]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: list[dict[str, float]]) -> str:
    lines = [
        "| Disclosed claims | VP size (B) | Encrypted VP (B) | Build VP (ms) | Verify VP, median [IQR] (ms) |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['disclosed_claims']} | {row['vp_bytes']:,} | {row['sealed_vp_bytes']:,} "
            f"| {row['create_vp_ms_median']:.2f} | {row['verify_ms_median']:.2f} "
            f"[{row['verify_ms_p25']:.2f}-{row['verify_ms_p75']:.2f}] |"
        )
    return "\n".join(lines)


def plot(rows: list[dict[str, float]], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    series, muted, grid, ink, surface = "#2a78d6", "#898781", "#e1e0d9", "#3d3c38", "#fcfcfb"
    x = [row["disclosed_claims"] for row in rows]
    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 4.2), facecolor=surface)
    for axis in (left, right):
        axis.set_facecolor(surface)
        axis.grid(axis="y", color=grid, linewidth=0.8)
        axis.set_axisbelow(True)
        for side in ("top", "right"):
            axis.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            axis.spines[side].set_color(grid)
        axis.tick_params(colors=muted, labelsize=9)
        axis.set_xlabel("Disclosed claims", color=muted, fontsize=9)
        axis.set_xticks(x)

    vp = [row["vp_bytes"] / 1024 for row in rows]
    left.plot(x, vp, color=series, linewidth=2, marker="o", markersize=6)
    vc = rows[0]["vc_bytes"] / 1024
    left.axhline(vc, color=muted, linewidth=1, linestyle=(0, (4, 3)))
    left.annotate(f"full credential in the wallet: {vc:.1f} KiB", (x[-1], vc), xytext=(0, -14),
                  textcoords="offset points", ha="right", color=muted, fontsize=9)
    left.set_ylim(0, max(max(vp), vc) * 1.18)
    left.set_title("Presentation size (KiB)", loc="left", color=ink, fontsize=11)

    median = [row["verify_ms_median"] for row in rows]
    right.fill_between(x, [row["verify_ms_p25"] for row in rows], [row["verify_ms_p75"] for row in rows],
                       color=series, alpha=0.15, linewidth=0)
    right.plot(x, median, color=series, linewidth=2, marker="o", markersize=6)
    right.set_ylim(0, max(row["verify_ms_p75"] for row in rows) * 1.25)
    right.set_title("Verifier latency, steps 7.A-7.F (ms, median and IQR)", loc="left", color=ink, fontsize=11)

    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=surface)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=50, help="repetitions per configuration")
    parser.add_argument("--out", type=Path, default=Path("benchmarks/results"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)

    rows = measure(args.runs)
    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(rows, args.out / "results.csv")
    table = markdown_table(rows)
    environment = f"Python {platform.python_version()} on {platform.system()} ({platform.machine()}), {args.runs} runs"
    (args.out / "results.md").write_text(f"{table}\n\n_{environment}_\n", encoding="utf-8")
    print(f"\nCredential size in the wallet: {rows[0]['vc_bytes']:,} bytes\n\n{table}\n\n{environment}")
    try:
        plot(rows, args.out / "benchmark.png")
        print(f"Plot written to {args.out / 'benchmark.png'}")
    except ImportError:
        print("matplotlib not installed: plot skipped (pip install matplotlib)")


if __name__ == "__main__":
    main()
