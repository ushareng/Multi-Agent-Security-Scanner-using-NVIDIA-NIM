"""
agents/ingestion_agent.py
Ingestion Agent — clones/reads the target codebase, normalizes files,
detects languages, chunks large files, and builds the file index.
"""

import os
import hashlib
import re
from pathlib import Path
from memory_store import MemoryStore

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", "coverage", "vendor",
}

MAX_FILE_SIZE_BYTES = 200_000   # Skip files > 200KB (minified/generated)
CHUNK_SIZE_LINES = 150          # Chunk large files into 150-line segments


class IngestionAgent:
    def __init__(self, store: MemoryStore):
        self.store = store
        self.max_files = int(os.getenv("MAX_FILES", 50))

    def run(self, target: str) -> list[dict]:
        """
        Main entry — accepts local path or GitHub URL.
        Returns list of file chunks ready for static scan.
        """
        print(f"[Ingestion] Starting ingestion for: {target}")

        if target.startswith("http") or target.startswith("git@"):
            local_path = self._clone_repo(target)
        else:
            local_path = os.path.abspath(target)
            if not os.path.exists(local_path):
                raise FileNotFoundError(f"Target path not found: {local_path}")

        chunks = self._walk_and_chunk(local_path)
        print(f"[Ingestion] Produced {len(chunks)} code chunks from {self.store.scan_metadata['files_scanned']} files")
        return chunks

    def _clone_repo(self, url: str) -> str:
        if not GIT_AVAILABLE:
            raise RuntimeError("gitpython not installed. Run: pip install gitpython")
        clone_dir = f"/tmp/audit_{hashlib.md5(url.encode()).hexdigest()[:8]}"
        if os.path.exists(clone_dir):
            print(f"[Ingestion] Using cached clone at {clone_dir}")
            return clone_dir
        print(f"[Ingestion] Cloning {url} to {clone_dir}")
        git.Repo.clone_from(url, clone_dir, depth=1)
        return clone_dir

    def _walk_and_chunk(self, root: str) -> list[dict]:
        chunks = []
        file_count = 0

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in place so os.walk doesn't descend into them
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for fname in filenames:
                if file_count >= self.max_files:
                    print(f"[Ingestion] MAX_FILES={self.max_files} reached, stopping.")
                    return chunks

                ext = Path(fname).suffix.lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue

                fpath = os.path.join(dirpath, fname)
                if os.path.getsize(fpath) > MAX_FILE_SIZE_BYTES:
                    continue

                language = SUPPORTED_EXTENSIONS[ext]
                relative_path = os.path.relpath(fpath, root)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
                self.store.file_index[relative_path] = {
                    "hash": file_hash,
                    "language": language,
                    "size": len(content),
                    "lines": content.count("\n"),
                }

                file_chunks = self._chunk_file(content, relative_path, language)
                chunks.extend(file_chunks)
                file_count += 1
                self.store.scan_metadata["files_scanned"] += 1

        return chunks

    def _chunk_file(self, content: str, filepath: str, language: str) -> list[dict]:
        """Split large files into overlapping chunks for context preservation."""
        lines = content.splitlines()
        if len(lines) <= CHUNK_SIZE_LINES:
            return [{
                "filepath": filepath,
                "language": language,
                "content": content,
                "start_line": 1,
                "end_line": len(lines),
            }]

        chunks = []
        overlap = 20  # lines of overlap between chunks for context
        i = 0
        while i < len(lines):
            end = min(i + CHUNK_SIZE_LINES, len(lines))
            chunk_content = "\n".join(lines[i:end])
            chunks.append({
                "filepath": filepath,
                "language": language,
                "content": chunk_content,
                "start_line": i + 1,
                "end_line": end,
            })
            i += CHUNK_SIZE_LINES - overlap

        return chunks
