from sentinel.enrichment.dependencies import is_dependency_file, parse_dependency_files


def test_parse_npm_and_python_dependency_files():
    refs = parse_dependency_files(
        {
            "package.json": '{"dependencies":{"left-pad":"^1.3.0"},"devDependencies":{"vite":"~5.2.0"}}',
            "requirements.txt": "fastapi==0.115.0\n# comment\n-r other.txt\n",
            "pyproject.toml": '[project]\ndependencies = ["httpx==0.28.1"]\n',
        }
    )

    assert {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"} in refs
    assert {"name": "vite", "version": "5.2.0", "ecosystem": "npm"} in refs
    assert {"name": "fastapi", "version": "0.115.0", "ecosystem": "pypi"} in refs
    assert {"name": "httpx", "version": "0.28.1", "ecosystem": "pypi"} in refs


def test_dependency_file_path_detection_is_separator_safe():
    assert is_dependency_file("apps/api/requirements.txt")
    assert is_dependency_file(r"apps\web\package-lock.json")
    assert not is_dependency_file("src/app.py")
