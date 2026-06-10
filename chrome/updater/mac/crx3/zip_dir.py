#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    os.pardir,
    os.pardir,
    os.pardir,
    os.pardir,
    "build")))
import zip_helpers

def main():
    if len(sys.argv) != 3:
        return 1

    source_dir = sys.argv[1]
    output_zip = sys.argv[2]

    inputs = []
    for root, _, files in os.walk(source_dir):
        for f in files:
            if f.endswith("_stamp") or f == ".stamp":
                continue
            inputs.append(os.path.join(root, f))

    zip_helpers.add_files_to_zip(
        inputs,
        output_zip,
        base_dir=source_dir,
        compress=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
