from setuptools import setup, find_packages

setup(
    name="straz", # Replace with your actual project name if different
    version="0.1.0", # Replace with your version
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        # List your project's dependencies here, e.g.:
        "flask",
        "cryptography",
        "requests",
        "python-dotenv",
        "websockets",
        "aiohttp",
        "numpy",
        "scipy",
        "liboqs-python",
        "pycryptodome",
        "liboqs",
        "pqcrypto",
        "pynacl",
        "pyopenssl",
        "cryptography-vectors",
        # Add pytest and other dev dependencies if needed for editable installs
        "pytest",
        "black",
        "mypy",
        "pylint",
        "pytest-asyncio",
        "pytest-cov",
        "pytest-mock",
        "pytest-timeout",
        "pytest-xdist",
        "pytest-benchmark",
        "pytest-env",
        "pytest-randomly",
        "pytest-sugar",
        "pytest-html",
        "pytest-metadata",
        "pytest-ordering",
        "pytest-repeat",
        "pytest-rerunfailures",
        "pytest-selenium",
        "pytest-socket",
        "pytest-subtests",
        "pytest-tldr",
        "pytest-watch",
        "pytest-xprocess",
        "pytest-xvfb",
    ],
    python_requires=">=3.8", # Specify your minimum Python version
    author="Your Name", # Replace with your name
    author_email="your.email@example.com", # Replace with your email
    description="A short description of your project", # Replace with a description
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/straz", # Replace with your repo URL
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License", # Replace with your license
        "Operating System :: OS Independent",
    ],
) 