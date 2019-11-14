import os.path

import setuptools

root_dir = os.path.abspath(os.path.dirname(__file__))
readme_file = os.path.join(root_dir, "README.rst")
with open(readme_file, encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="aioquic",
    version="0.8.3",
    description="An implementation of QUIC and HTTP/3",
    long_description=long_description,
    url="https://github.com/aiortc/aioquic",
    author="Jeremy Lainé",
    author_email="jeremy.laine@m4x.org",
    license="BSD",
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP",
    ],
    ext_modules=[
        setuptools.Extension("aioquic._buffer", sources=["src/aioquic/_buffer.c"],
            extra_compile_args=["-std=c99"]
            ),
        setuptools.Extension(
            "aioquic._crypto", libraries=["crypto"], sources=["src/aioquic/_crypto.c"],
            extra_compile_args=["-std=c99"]
            ),
    ],
    package_dir={"": "src"},
    package_data={"aioquic": ["py.typed", "_buffer.pyi", "_crypto.pyi"]},
    packages=["aioquic", "aioquic.asyncio", "aioquic.h0", "aioquic.h3", "aioquic.quic"],
    install_requires=[
        "cryptography >= 2.5",
        'dataclasses; python_version < "3.7"',
        "pylsqpack >= 0.3.3, < 0.4.0",
    ],
)
