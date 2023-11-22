#!/bin/env python3

import glob
import gzip
import os
import re
import sys
import yaml

SNAPDIR = "/snap/"
bases = []

def read_snap_manifest(snap_name):
    manifest = "snap/manifest.yaml"
    dpkg = "usr/share/snappy/dpkg.yaml"
    changelog = "doc/linux-modules-*/changelog.Debian.gz"
    man_yaml = None
    section = None

    fn = os.path.join(SNAPDIR, snap_name, "current/")

    if os.path.exists(os.path.join(fn, dpkg)):
        with open(os.path.join(fn, dpkg), 'r') as fd:
            man_yaml = yaml.safe_load(fd)
        section = "packages"
    elif os.path.exists(os.path.join(fn, manifest)):
        with open(os.path.join(fn, manifest), 'r') as fd:
            man_yaml = yaml.safe_load(fd)
        section = "primed-stage-packages"
    else:
        for filename in glob.glob(os.path.join(fn, changelog)):
            with gzip.open(filename, 'rt') as fd:
                lines = fd.readlines()
                release = lines[0].split(' ')[2]
                base_kernel_entry = release.replace(';', '/') + 'linux:'
                kernel_major_version = re.search(r'([\d|\.]+)-\d+[\.|\d]+', lines[0])[1]
                for line in lines:
                    if base_kernel_entry in line:
                        matched_version = re.search(r'(' + kernel_major_version + r'-\d+)[\.|\d]+', line)
                        base_kernel_version = matched_version[1]
                        base_kernel_full_version = matched_version[0]
                        break
                section = "packages"
                man_yaml = {section: []}
                man_yaml[section].append('linux-image-' + base_kernel_version + '-generic=' + base_kernel_full_version)

    return (man_yaml, section)

def parse_snap_manifest(snap_name):
    data = {}
    base = snap_name
    man_yaml, section = read_snap_manifest(snap_name)

    if man_yaml:
        if "base" in man_yaml:
            base = man_yaml["base"]

        for entry in man_yaml[section]:
            if "=" not in entry:
                print("'%s' not properly formatted. Skipping" % entry)
                continue
            pkg, ver = entry.split("=")
            if pkg not in data:
                data[pkg] = ver
            else:
                print(pkg, ver, data[pkg])

    return (data, base)

def generate_manifest(snap_name):
    (data, base) = parse_snap_manifest(snap_name)

    if not data:
        return

    if base not in bases:
        bases.append(base)
        if os.path.exists(f"manifest.{base}"):
            os.rename(f"manifest.{base}", f"manifest.{base}.old")

    with open(f"manifest.{base}", 'a') as fd:
        for pkg, ver in data.items():
            fd.write(f"{pkg} {ver} {snap_name}\n")


def main():
    for d in os.listdir(SNAPDIR):
        generate_manifest(d)

    print("REMEMBER TO RENAME THE FILE TO 'manifest'")

if __name__ == "__main__":
    main()
