#!/usr/bin/env python3
"""Exercise concurrent read-only Store clients against one daemon-shaped writer."""

import argparse
from contextlib import nullcontext
import multiprocessing
from queue import Empty
import tempfile
import threading
import time

from taema.store.knowledge import Store


def read_passes(state_dir, index, stop, counts, failures):
    while not stop.is_set():
        try:
            client = Store(state_dir, {}, read_only=True)
            client.peek("stress")
            counts[index] += 1
        except Exception as error:  # report SQLite lock and transaction errors
            failures.put("reader %d: %s: %s" % (index, type(error).__name__, error))
            stop.set()
            return
        stop.wait(0.01)


def run(duration, readers, state_dir=None, report_interval=60):
    temporary = tempfile.TemporaryDirectory() if state_dir is None else nullcontext()
    with temporary as directory:
        state_dir = state_dir or directory
        writer = Store(state_dir, {})
        writer.save()
        context = multiprocessing.get_context("spawn")
        stop = context.Event()
        failures = context.Queue()
        counts = context.Array("L", readers + 1)

        def write_passes():
            while not stop.is_set():
                try:
                    writer.bump("stress", "seen")
                    writer.save()
                    counts[0] += 1
                except Exception as error:  # report SQLite lock and transaction errors
                    failures.put("writer: %s: %s" % (type(error).__name__, error))
                    stop.set()
                    return
                stop.wait(0.02)

        writer_thread = threading.Thread(target=write_passes, name="daemon-writer")
        reader_processes = [
            context.Process(
                target=read_passes,
                args=(state_dir, index + 1, stop, counts, failures),
                name="cli-reader-%d" % index,
            )
            for index in range(readers)
        ]
        workers = [writer_thread, *reader_processes]
        start = time.monotonic()
        deadline = start + duration
        writer_thread.start()
        for process in reader_processes:
            process.start()
        next_report = report_interval
        errors = []

        def drain_errors():
            while True:
                try:
                    errors.append(failures.get_nowait())
                except Empty:
                    return

        while not stop.is_set() and time.monotonic() < deadline:
            drain_errors()
            elapsed = time.monotonic() - start
            if elapsed >= next_report:
                print(
                    "progress %.0f/%.0f seconds: writes=%d reads=%s"
                    % (elapsed, duration, counts[0], list(counts[1:])),
                    flush=True,
                )
                next_report += report_interval
            stop.wait(min(1, deadline - time.monotonic()))
        stop.set()
        for worker in workers:
            worker.join(timeout=5)
        drain_errors()
        elapsed = time.monotonic() - start
        if any(worker.is_alive() for worker in workers):
            errors.append("worker did not stop")
        errors.extend(
            "%s exited with status %d" % (worker.name, worker.exitcode)
            for worker in reader_processes
            if worker.exitcode not in (0, None)
        )
        failures.close()
        failures.join_thread()
        if errors:
            raise RuntimeError("; ".join(errors))
        if elapsed < duration:
            raise RuntimeError("stress stopped early after %.1f seconds" % elapsed)
        print(
            "passed %.1f seconds: writes=%d reads=%s lock_errors=0"
            % (elapsed, counts[0], list(counts[1:])),
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=600.0)
    parser.add_argument("--readers", type=int, default=3)
    parser.add_argument("--state-dir")
    args = parser.parse_args()
    if args.duration <= 0 or args.readers <= 0:
        parser.error("duration and readers must be positive")
    run(args.duration, args.readers, args.state_dir)


if __name__ == "__main__":
    main()
