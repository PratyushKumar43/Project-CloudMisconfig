from setuptools import setup, find_packages

setup(
    name="aws-config-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "boto3",
        "sqlalchemy",
        "pydantic",
        "pydantic-settings",
        "python-dotenv",
        "aiosqlite",
    ],
)
