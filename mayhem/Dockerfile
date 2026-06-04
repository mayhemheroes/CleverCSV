FROM python:3.11-slim

# Install build dependencies for atheris (needs clang + compiler-rt for libFuzzer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-rt-dev \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Build and install atheris from source
RUN pip install --no-cache-dir atheris

# Install CleverCSV
# setup.py's _install_setup_requires uses MinimalDistribution(distutils.core.Distribution)
# which gained set_defaults in setuptools 59.x and lost it again in 66+.
# setuptools 63.4.3 is the last stable release where both set_defaults and dist_info work.
ADD . /src
WORKDIR /src
RUN pip install --no-cache-dir "setuptools==63.4.3" wheel && \
    pip install --no-cache-dir --no-build-isolation .

CMD ["/src/mayhem/fuzz_reader.py"]
