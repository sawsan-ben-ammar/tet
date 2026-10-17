"""Inline the rules, config template and entrypoint into the Suricata DaemonSet.

    python lab/k8s/suricata/render.py <suricata-image> > lab/k8s/suricata/suricata.gen.yaml
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def indent(path, n):
    pad = " " * n
    return "".join(pad + line for line in open(path).read().splitlines(keepends=True))


def main(image):
    sk = open(os.path.join(HERE, "suricata.yaml")).read()
    sk = sk.replace("__RULES__", indent(os.path.join(HERE, "dos-home.rules"), 4).rstrip("\n"))
    sk = sk.replace("__TMPL__", indent(os.path.join(HERE, "suricata.yaml.tmpl"), 4).rstrip("\n"))
    sk = sk.replace("__ENTRY__", indent(os.path.join(HERE, "entrypoint.sh"), 4).rstrip("\n"))
    sk = sk.replace("IMAGE_PLACEHOLDER", image)
    sys.stdout.write(sk)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "jasonish/suricata:7.0.8")
