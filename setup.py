from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="auth-middleware",
    version="2.0.0",
    author="Dev Wazobia",
    author_email="developer@wazobia.tech",
    description="Authentication middleware for Python services with platform, project, and service token authentication.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="git@bitbucket.org:wazobiatech/python_auth_middleware.git",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "redis>=4.5.0",
        "requests>=2.28.0",
        "PyJWT>=2.8.0",
        "cryptography>=41.0.0",
        "python-jose[cryptography]>=3.3.0",
        "flask>=2.3.0",
        "fastapi>=0.100.0",
        "graphene>=3.3",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.4.0",
        ]
    }
)