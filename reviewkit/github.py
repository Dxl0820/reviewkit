"""GitHub API integration for fetching PR data."""

import os
import requests


GITHUB_API = "https://api.github.com"


def _get_headers():
    """Build request headers with optional token."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def get_repo_info(owner, repo):
    """Get repository information."""
    resp = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=_get_headers())
    resp.raise_for_status()
    return resp.json()


def get_pr_diff(owner, repo, pr_number):
    """Get the diff of a pull request."""
    headers = _get_headers()
    headers["Accept"] = "application/vnd.github.v3.diff"
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}",
        headers=headers,
    )
    resp.raise_for_status()
    return resp.text


def get_pr_files(owner, repo, pr_number):
    """Get list of files changed in a pull request."""
    files = []
    page = 1
    while True:
        resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files",
            headers=_get_headers(),
            params={"per_page": 100, "page": page},
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        files.extend(batch)
        page += 1
    return [f["filename"] for f in files]


def get_pr_info(owner, repo, pr_number):
    """Get pull request metadata."""
    resp = requests.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}",
        headers=_get_headers(),
    )
    resp.raise_for_status()
    return resp.json()
