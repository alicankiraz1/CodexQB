from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_IO_PATH = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/artifact_io.py"


def load_artifact_io_module():
    spec = importlib.util.spec_from_file_location("codexqb_artifact_io", ARTIFACT_IO_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load artifact_io from {ARTIFACT_IO_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ARTIFACT_IO = load_artifact_io_module()


class ArtifactIOTests(unittest.TestCase):
    def open_directory(self, path: Path) -> int:
        return os.open(path, ARTIFACT_IO.secure_directory_open_flags())

    def test_parent_authority_failure_rolls_back_new_directory(self) -> None:
        for failing_call in (1, 2, 3):
            with self.subTest(failing_call=failing_call), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                root_fd = self.open_directory(root)
                calls = 0

                def authority(_descriptor: int) -> bool:
                    nonlocal calls
                    calls += 1
                    return calls != failing_call

                try:
                    with self.assertRaisesRegex(
                        ValueError,
                        "artifact_parent_authority_rejected",
                    ):
                        ARTIFACT_IO.open_or_create_child_directory(
                            root_fd,
                            "Planner-docs",
                            create=True,
                            parent_authority_validator=authority,
                        )
                finally:
                    os.close(root_fd)

                self.assertEqual(calls, failing_call)
                self.assertFalse((root / "Planner-docs").exists())

    def test_atomic_write_rejects_final_target_symlink_without_modifying_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact_dir = root / "artifacts"
            artifact_dir.mkdir()
            victim = root / "victim.txt"
            victim.write_text("preserve victim\n", encoding="utf-8")
            target = artifact_dir / "Result.json"
            target.symlink_to(victim)
            directory_fd = self.open_directory(artifact_dir)
            try:
                with self.assertRaisesRegex(ValueError, "artifact_target_must_be_regular_file"):
                    ARTIFACT_IO.atomic_write_bytes_at(directory_fd, target.name, b"replacement\n")
            finally:
                os.close(directory_fd)

            self.assertTrue(target.is_symlink())
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve victim\n")

    def test_all_text_artifact_formats_reject_secrets_without_partial_writes_or_echo(self) -> None:
        fixture = "sk-" + "S" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            directory_fd = self.open_directory(artifact_dir)
            cases = [
                (
                    "json",
                    "Progress.json",
                    lambda: ARTIFACT_IO.atomic_write_json_at(
                        directory_fd,
                        "Progress.json",
                        {"summary": {"evidence": [fixture]}},
                    ),
                ),
                (
                    "jsonl",
                    "Events.jsonl",
                    lambda: ARTIFACT_IO.atomic_write_text_at(
                        directory_fd,
                        "Events.jsonl",
                        '{"actor":"' + fixture + '"}\n',
                    ),
                ),
                (
                    "markdown",
                    "Goal-Prompt.md",
                    lambda: ARTIFACT_IO.atomic_write_text_at(
                        directory_fd,
                        "Goal-Prompt.md",
                        "Evidence: " + fixture + "\n",
                    ),
                ),
                (
                    "patch",
                    "Review-Package.patch",
                    lambda: ARTIFACT_IO.atomic_write_text_at(
                        directory_fd,
                        "Review-Package.patch",
                        "+TOKEN=" + fixture + "\n",
                    ),
                ),
            ]
            try:
                for format_name, name, writer in cases:
                    with self.subTest(format=format_name):
                        target = artifact_dir / name
                        target.write_text("preserve existing\n", encoding="utf-8")
                        try:
                            writer()
                        except ValueError as exc:
                            if fixture in str(exc):
                                self.fail(f"artifact rejection leaked fixture for {format_name}")
                        else:
                            self.fail(f"artifact writer accepted fixture for {format_name}")
                        self.assertEqual(target.read_text(encoding="utf-8"), "preserve existing\n")
            finally:
                os.close(directory_fd)

    def test_semantic_json_jsonl_and_markdown_encodings_are_rejected_before_write(self) -> None:
        fixture = "sk-" + "A" * 40
        escaped = "sk-" + "\\u0041" * 40
        entity_encoded = "".join(f"&#{ord(character)};" for character in fixture)
        ansi_split = fixture[:8] + "\x1b[32m" + fixture[8:]
        cases = [
            ("Goal-Run.json", ('{"summary":"' + escaped + '"}\n').encode("utf-8")),
            (
                "Progress.json",
                ('{"summary":"' + escaped + '","summary":"safe"}\n').encode("utf-8"),
            ),
            ("Events.jsonl", ('{"actor":"' + escaped + '"}\n').encode("utf-8")),
            ("Goal-Prompt.md", ("Evidence: " + entity_encoded + "\n").encode("utf-8")),
            ("Report.md", ("Evidence: " + ansi_split + "\n").encode("utf-8")),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            directory_fd = self.open_directory(artifact_dir)
            try:
                for name, encoded in cases:
                    with self.subTest(name=name):
                        try:
                            ARTIFACT_IO.atomic_write_bytes_at(directory_fd, name, encoded)
                        except ValueError as exc:
                            self.assertNotIn(fixture, str(exc))
                        else:
                            self.fail(f"semantic secret encoding was accepted for {name}")
                        self.assertFalse((artifact_dir / name).exists())
            finally:
                os.close(directory_fd)

    def test_atomic_write_uses_distinct_exclusive_no_follow_temporaries_in_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            directory_fd = self.open_directory(artifact_dir)
            real_open = os.open
            temporary_opens: list[tuple[str, int, int]] = []

            def observing_open(path, flags, mode=0o777, *, dir_fd=None):
                if flags & os.O_CREAT:
                    temporary_opens.append((os.fspath(path), flags, dir_fd))
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with mock.patch.object(ARTIFACT_IO.os, "open", side_effect=observing_open):
                    ARTIFACT_IO.atomic_write_bytes_at(directory_fd, "first.txt", b"first\n")
                    ARTIFACT_IO.atomic_write_bytes_at(directory_fd, "second.txt", b"second\n")
            finally:
                os.close(directory_fd)

            self.assertEqual(len(temporary_opens), 2)
            self.assertNotEqual(temporary_opens[0][0], temporary_opens[1][0])
            for name, flags, opened_dir_fd in temporary_opens:
                self.assertEqual(opened_dir_fd, directory_fd)
                self.assertNotIn("/", name)
                self.assertNotIn("\\", name)
                self.assertTrue(flags & os.O_EXCL)
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertFalse((artifact_dir / name).exists())
            self.assertEqual((artifact_dir / "first.txt").read_bytes(), b"first\n")
            self.assertEqual((artifact_dir / "second.txt").read_bytes(), b"second\n")

    def test_atomic_write_failure_preserves_existing_target_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            target = artifact_dir / "Progress.json"
            target.write_bytes(b'{"status":"old"}\n')
            entries_before = set(artifact_dir.iterdir())
            directory_fd = self.open_directory(artifact_dir)
            try:
                with mock.patch.object(ARTIFACT_IO.os, "write", side_effect=OSError("synthetic write failure")):
                    with self.assertRaisesRegex(OSError, "synthetic write failure"):
                        ARTIFACT_IO.atomic_write_bytes_at(directory_fd, target.name, b'{"status":"new"}\n')
            finally:
                os.close(directory_fd)

            self.assertEqual(target.read_bytes(), b'{"status":"old"}\n')
            self.assertEqual(set(artifact_dir.iterdir()), entries_before)

    def test_atomic_replace_failure_preserves_existing_target_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            target = artifact_dir / "Progress.json"
            target.write_bytes(b'{"status":"old"}\n')
            entries_before = set(artifact_dir.iterdir())
            directory_fd = self.open_directory(artifact_dir)
            try:
                with mock.patch.object(ARTIFACT_IO.os, "replace", side_effect=OSError("synthetic replace failure")):
                    with self.assertRaisesRegex(OSError, "synthetic replace failure"):
                        ARTIFACT_IO.atomic_write_bytes_at(directory_fd, target.name, b'{"status":"new"}\n')
            finally:
                os.close(directory_fd)

            self.assertEqual(target.read_bytes(), b'{"status":"old"}\n')
            self.assertEqual(set(artifact_dir.iterdir()), entries_before)

    def test_atomic_write_retries_complete_short_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            payload = b'{"event_type":"complete"}\n'
            directory_fd = self.open_directory(artifact_dir)
            real_write = os.write
            write_sizes: list[int] = []

            def short_write(file_fd: int, encoded: bytes) -> int:
                chunk = encoded[: min(3, len(encoded))]
                write_sizes.append(len(chunk))
                return real_write(file_fd, chunk)

            try:
                with mock.patch.object(ARTIFACT_IO.os, "write", side_effect=short_write):
                    ARTIFACT_IO.atomic_write_bytes_at(directory_fd, "Events.jsonl", payload)
            finally:
                os.close(directory_fd)

            self.assertGreater(len(write_sizes), 1)
            self.assertTrue(all(0 < size <= 3 for size in write_sizes))
            self.assertEqual((artifact_dir / "Events.jsonl").read_bytes(), payload)

    def test_atomic_write_fsyncs_file_then_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_dir = Path(temp_dir)
            directory_fd = self.open_directory(artifact_dir)
            real_fsync = os.fsync
            fsync_kinds: list[str] = []

            def recording_fsync(file_fd: int) -> None:
                mode = os.fstat(file_fd).st_mode
                fsync_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
                real_fsync(file_fd)

            try:
                with mock.patch.object(ARTIFACT_IO.os, "fsync", side_effect=recording_fsync):
                    ARTIFACT_IO.atomic_write_bytes_at(directory_fd, "Goal-Run.json", b"{}\n")
            finally:
                os.close(directory_fd)

            self.assertEqual(fsync_kinds, ["file", "directory"])

    def test_unlink_rejects_symlink_and_special_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact_dir = root / "artifacts"
            artifact_dir.mkdir()
            victim = root / "victim.txt"
            victim.write_text("preserve victim\n", encoding="utf-8")
            symlink = artifact_dir / "linked-artifact"
            symlink.symlink_to(victim)
            fifo = artifact_dir / "artifact.fifo"
            if not hasattr(os, "mkfifo"):
                self.skipTest("mkfifo is unavailable on this host")
            os.mkfifo(fifo)
            directory_fd = self.open_directory(artifact_dir)
            try:
                for name in (symlink.name, fifo.name):
                    with self.subTest(name=name):
                        with self.assertRaisesRegex(ValueError, "artifact_target_must_be_regular_file"):
                            ARTIFACT_IO.unlink_regular_at(directory_fd, name)
            finally:
                os.close(directory_fd)

            self.assertTrue(symlink.is_symlink())
            self.assertTrue(fifo.exists())
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve victim\n")


if __name__ == "__main__":
    unittest.main()
