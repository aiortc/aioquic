import sys

import setuptools

if sys.platform == "win32":
    extra_compile_args = []
else:
    extra_compile_args = ["-std=c99"]


setuptools.setup(
    ext_modules=[
        setuptools.Extension(
            "aioquic._buffer",
            extra_compile_args=extra_compile_args,
            sources=["src/aioquic/_buffer.c"],
            define_macros=[("Py_LIMITED_API", "0x030B0000")],
            py_limited_api=True,
        ),
    ],
    options={"bdist_wheel": {"py_limited_api": "cp311"}},
)
