import sys

import setuptools
from wheel.bdist_wheel import bdist_wheel

if sys.platform == "win32":
    extra_compile_args = []
else:
    extra_compile_args = ["-std=c99"]


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            return "cp310", "abi3", plat

        return python, abi, plat


setuptools.setup(
    ext_modules=[
        setuptools.Extension(
            "aioquic._buffer",
            extra_compile_args=extra_compile_args,
            sources=["src/aioquic/_buffer.c"],
            define_macros=[("Py_LIMITED_API", "0x030A0000")],
            py_limited_api=True,
        ),
    ],
    cmdclass={"bdist_wheel": bdist_wheel_abi3},
)
