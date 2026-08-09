from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional in minimal agent installs
    Draft202012Validator = None

from pcbex_agent import cli
from pcbex_agent import manufacturing_replay as replay_module
from pcbex_agent.bounded_process import BoundedProcessResult
from pcbex_agent.manufacturing_replay import (
    ManufacturingReplayError,
    manufacturing_package_replay_result_json_schema,
    replay_manufacturing_package,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_fake_pcbex(root: Path, package: bytes, **configuration: object) -> list[str]:
    (root / "fake-package.bin").write_bytes(package)
    (root / "fake-config.json").write_text(
        json.dumps(configuration), encoding="utf-8"
    )
    wrapper = root / "fake-fabricate.py"
    wrapper.write_text(
        r'''from __future__ import annotations
import json
from pathlib import Path
import sys

root = Path(__file__).parent
config = json.loads((root / "fake-config.json").read_text(encoding="utf-8"))
argv = sys.argv[1:]
(root / "invocation.json").write_text(json.dumps(argv), encoding="utf-8")
if not argv or argv[0] != "fabricate":
    raise SystemExit(91)

def option(name: str) -> str | None:
    prefix = "--" + name + "="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == "--" + name and index + 1 < len(argv):
            return argv[index + 1]
    return None

board = Path(argv[1])
output = Path(option("output-dir"))
output.mkdir()
observation = {"board_name": board.name}
for extension, key in ((".kicad_pro", "project"), (".kicad_dru", "rules")):
    candidate = board.with_suffix(extension)
    if candidate.exists():
        observation[key] = candidate.read_bytes().hex()
for option_name in ("fab-profile", "physical-profile"):
    selected = option(option_name)
    if selected:
        selected_path = Path(selected)
        observation["profile"] = {
            "name": selected_path.name,
            "bytes": selected_path.read_bytes().hex(),
        }
(root / "stage-observation.json").write_text(
    json.dumps(observation), encoding="utf-8"
)
package = (root / "fake-package.bin").read_bytes()
if config.get("mismatch"):
    package += b"mismatch"
fresh = output / "manufacturing.zip"
if config.get("symlink_output"):
    target = root / "symlink-package.bin"
    target.write_bytes(package)
    fresh.symlink_to(target)
else:
    fresh.write_bytes(package)
if config.get("mutate_staged"):
    board.write_bytes(board.read_bytes() + b"changed")
for key in (
    "mutate_caller",
    "mutate_retained",
    "mutate_profile",
    "mutate_project",
    "mutate_rules",
):
    path = config.get(key)
    if path:
        Path(path).write_bytes(Path(path).read_bytes() + b"changed")
raise SystemExit(int(config.get("returncode", 0)))
''',
        encoding="utf-8",
    )
    return [sys.executable, str(wrapper)]


class ManufacturingReplayTests(unittest.TestCase):
    def _sources(self, root: Path) -> tuple[Path, Path, bytes]:
        board = root / "controller.kicad_pcb"
        package = root / "retained-manufacturing.zip"
        package_raw = b"PK\x03\x04deterministic-test-package"
        board.write_bytes(b"(kicad_pcb (version 20240108))\n")
        package.write_bytes(package_raw)
        return board, package, package_raw

    def test_success_is_closed_path_free_and_schema_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            project = root / "caller-project.any"
            rules = root / "caller-rules.any"
            project.write_bytes(b'{"board": {}}\n')
            rules.write_bytes(b"(version 1)\n")
            command = _write_fake_pcbex(root, package_raw)

            result = replay_manufacturing_package(
                board,
                package,
                command,
                kicad_project=project,
                kicad_rules=rules,
            )

            self.assertEqual(result["schema_version"], 1)
            self.assertEqual(
                result["verification_scope"],
                "manufacturing-package-fresh-replay-v1",
            )
            self.assertTrue(result["verified"])
            self.assertEqual(
                result["board"],
                {
                    "name": "controller.kicad_pcb",
                    "bytes": len(board.read_bytes()),
                    "sha256": _sha(board.read_bytes()),
                },
            )
            self.assertEqual(result["project"]["sha256"], _sha(project.read_bytes()))
            self.assertEqual(result["rules"]["sha256"], _sha(rules.read_bytes()))
            self.assertEqual(result["profile"], {"kind": "none"})
            self.assertEqual(result["package"]["retained"], result["package"]["fresh"])
            self.assertTrue(result["package"]["identical"])
            rendered = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn(str(command[1]), rendered)
            self.assertNotIn(package_raw.hex(), rendered)

            invocation = json.loads((root / "invocation.json").read_text())
            staged_board = Path(invocation[1])
            self.assertEqual(staged_board.name, board.name)
            observation = json.loads((root / "stage-observation.json").read_text())
            self.assertEqual(bytes.fromhex(observation["project"]), project.read_bytes())
            self.assertEqual(bytes.fromhex(observation["rules"]), rules.read_bytes())
            self.assertTrue(any(value.startswith("--kicad-cli=") for value in invocation))
            self.assertTrue(any(value.startswith("--timeout-seconds=") for value in invocation))

            if Draft202012Validator is not None:
                validator = Draft202012Validator(
                    manufacturing_package_replay_result_json_schema()
                )
                self.assertEqual(list(validator.iter_errors(result)), [])

    def test_external_profile_retains_non_default_portable_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            profile = root / "JLC-2L-production.rev7.json"
            profile_raw = b'{"schema_version":1}\n'
            profile.write_bytes(profile_raw)
            command = _write_fake_pcbex(root, package_raw)

            result = replay_manufacturing_package(
                board, package, command, fab_profile=profile
            )

            self.assertEqual(
                result["profile"],
                {
                    "kind": "dfm-file",
                    "source": {
                        "name": profile.name,
                        "bytes": len(profile_raw),
                        "sha256": _sha(profile_raw),
                    },
                },
            )
            invocation = json.loads((root / "invocation.json").read_text())
            profile_argument = next(
                value for value in invocation if value.startswith("--fab-profile=")
            )
            staged_profile = Path(profile_argument.split("=", 1)[1])
            self.assertEqual(staged_profile.name, profile.name)
            observation = json.loads((root / "stage-observation.json").read_text())
            self.assertEqual(observation["profile"]["name"], profile.name)
            self.assertEqual(
                bytes.fromhex(observation["profile"]["bytes"]), profile_raw
            )

    def test_builtin_and_physical_profile_results_are_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            command = _write_fake_pcbex(root, package_raw)
            builtin = replay_manufacturing_package(
                board, package, command, fab="jlcpcb-2layer"
            )
            self.assertEqual(
                builtin["profile"], {"kind": "builtin", "id": "jlcpcb-2layer"}
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            physical = root / "assembly physical v2.json"
            physical.write_bytes(b'{"schema_version":2}\n')
            command = _write_fake_pcbex(root, package_raw)
            result = replay_manufacturing_package(
                board, package, command, physical_profile=physical
            )
            self.assertEqual(result["profile"]["kind"], "physical-file")
            self.assertEqual(result["profile"]["source"]["name"], physical.name)

    def test_profile_selections_are_exclusive_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            profile = root / "profile.json"
            profile.write_bytes(b"{}")
            command = _write_fake_pcbex(root, package_raw)
            with self.assertRaisesRegex(ManufacturingReplayError, "mutually exclusive"):
                replay_manufacturing_package(
                    board,
                    package,
                    command,
                    fab="jlcpcb-2layer",
                    fab_profile=profile,
                )
            with self.assertRaisesRegex(ManufacturingReplayError, "built-in"):
                replay_manufacturing_package(board, package, command, fab="")
            for unsafe_id in ("JLCPCB-2layer", "/tmp/private-profile", "bad_id"):
                with self.subTest(unsafe_id=unsafe_id), self.assertRaisesRegex(
                    ManufacturingReplayError, "built-in"
                ):
                    replay_manufacturing_package(
                        board, package, command, fab=unsafe_id
                    )
            with self.assertRaisesRegex(ManufacturingReplayError, "DFM profile source"):
                replay_manufacturing_package(
                    board, package, command, fab_profile=root / "missing.json"
                )

    def test_exact_mismatch_is_path_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            command = _write_fake_pcbex(root, package_raw, mismatch=True)
            with self.assertRaises(ManufacturingReplayError) as caught:
                replay_manufacturing_package(board, package, command)
            rendered = str(caught.exception)
            self.assertIn("did not reproduce", rendered)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn(board.name, rendered)

    def test_staged_and_caller_mutation_are_rejected(self):
        for configuration, expected in (
            ({"mutate_staged": True}, "staged manufacturing input changed"),
            ({"mutate_caller": "BOARD"}, "board source changed"),
            ({"mutate_retained": "PACKAGE"}, "retained package source changed"),
        ):
            with self.subTest(configuration=configuration):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    board, package, package_raw = self._sources(root)
                    resolved = {
                        key: (
                            str(board)
                            if value == "BOARD"
                            else str(package) if value == "PACKAGE" else value
                        )
                        for key, value in configuration.items()
                    }
                    command = _write_fake_pcbex(root, package_raw, **resolved)
                    with self.assertRaisesRegex(ManufacturingReplayError, expected):
                        replay_manufacturing_package(board, package, command)

        for option, label in (
            ("mutate_project", "KiCad project source changed"),
            ("mutate_rules", "KiCad rules source changed"),
            ("mutate_profile", "DFM profile source changed"),
        ):
            with self.subTest(option=option):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    board, package, package_raw = self._sources(root)
                    project = root / "project.input"
                    rules = root / "rules.input"
                    profile = root / "fab-profile.rev2.json"
                    project.write_bytes(b"project")
                    rules.write_bytes(b"rules")
                    profile.write_bytes(b"profile")
                    mutation_source = {
                        "mutate_project": project,
                        "mutate_rules": rules,
                        "mutate_profile": profile,
                    }[option]
                    command = _write_fake_pcbex(
                        root, package_raw, **{option: str(mutation_source)}
                    )
                    with self.assertRaisesRegex(ManufacturingReplayError, label):
                        replay_manufacturing_package(
                            board,
                            package,
                            command,
                            kicad_project=project,
                            kicad_rules=rules,
                            fab_profile=profile,
                        )

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unsupported")
    def test_symlink_sources_and_fresh_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            linked = root / "linked.kicad_pcb"
            try:
                linked.symlink_to(board)
            except OSError:
                self.skipTest("symlink creation is not permitted")
            command = _write_fake_pcbex(root, package_raw)
            with self.assertRaisesRegex(ManufacturingReplayError, "board source is invalid"):
                replay_manufacturing_package(linked, package, command)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            command = _write_fake_pcbex(root, package_raw, symlink_output=True)
            with self.assertRaisesRegex(ManufacturingReplayError, "fresh package source is invalid"):
                replay_manufacturing_package(board, package, command)

    def test_portable_leaf_checks_reject_windows_and_separator_risks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "retained.zip"
            package.write_bytes(b"package")
            for name in (
                ".kicad_pcb",
                "CON.kicad_pcb",
                "trailing .kicad_pcb ",
            ):
                board = root / name
                with self.subTest(name=name), self.assertRaisesRegex(
                    ManufacturingReplayError, "portable"
                ):
                    replay_manufacturing_package(board, package, "pcbex")
            self.assertFalse(replay_module._portable_leaf("bad\\name.kicad_pcb"))

            board = root / "board.kicad_pcb"
            board.write_bytes(b"board")
            profile = root / "AUX.json"
            with self.assertRaisesRegex(ManufacturingReplayError, "portable"):
                replay_manufacturing_package(
                    board, package, "pcbex", fab_profile=profile
                )

    def test_per_source_caps_and_aggregate_bound_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            command = _write_fake_pcbex(root, package_raw)
            original = replay_module.read_bytes
            observed: list[tuple[str, int]] = []

            def recording(path: object, *, max_bytes: int) -> bytes:
                observed.append((Path(path).name, max_bytes))
                return original(path, max_bytes=max_bytes)

            with mock.patch.object(replay_module, "read_bytes", side_effect=recording):
                replay_manufacturing_package(board, package, command)
            self.assertIn((board.name, replay_module.MAXIMUM_BOARD_BYTES), observed)
            self.assertIn((package.name, replay_module.MAXIMUM_PACKAGE_BYTES), observed)
            self.assertTrue(
                any(
                    name == "manufacturing.zip"
                    and maximum == replay_module.MAXIMUM_PACKAGE_BYTES
                    for name, maximum in observed
                )
            )

            with mock.patch.object(
                replay_module, "MAXIMUM_TOTAL_INPUT_BYTES", len(package_raw)
            ), self.assertRaisesRegex(ManufacturingReplayError, "aggregate bound"):
                replay_manufacturing_package(board, package, command)

    def test_child_timeout_has_strictly_larger_outer_supervisor_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            observed: dict[str, object] = {}

            def fake_run(argv: list[str], **kwargs: object) -> BoundedProcessResult:
                observed["argv"] = list(argv)
                observed["kwargs"] = dict(kwargs)
                output_arg = next(
                    value for value in argv if value.startswith("--output-dir=")
                )
                output = Path(output_arg.split("=", 1)[1])
                output.mkdir()
                (output / "manufacturing.zip").write_bytes(package_raw)
                return BoundedProcessResult(tuple(argv), 0, b"", b"")

            with mock.patch.object(replay_module, "run_bounded", side_effect=fake_run):
                replay_manufacturing_package(
                    board,
                    package,
                    ["trusted-wrapper", "pcbex"],
                    kicad_cli="trusted-kicad-cli",
                    timeout_seconds=80.0,
                )
            argv = observed["argv"]
            kwargs = observed["kwargs"]
            inner = float(
                next(
                    value.split("=", 1)[1]
                    for value in argv
                    if value.startswith("--timeout-seconds=")
                )
            )
            outer = float(kwargs["timeout_seconds"])
            self.assertGreater(outer, inner)
            self.assertEqual(argv[:3], ["trusted-wrapper", "pcbex", "fabricate"])
            self.assertIn("--kicad-cli=trusted-kicad-cli", argv)
            self.assertEqual(argv.count("--outer-process-tree-supervised"), 1)
            self.assertEqual(kwargs["max_stdout_bytes"], 1024 * 1024)
            self.assertEqual(kwargs["max_stderr_bytes"], 1024 * 1024)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group regression")
    def test_real_outer_timeout_reaps_kicad_after_pre_exec_delay(self):
        binary = os.environ.get("PCBEX_TEST_BINARY")
        if not binary:
            self.skipTest("PCBEX_TEST_BINARY is not supplied")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board = root / "board.kicad_pcb"
            retained = root / "retained.zip"
            marker = root / "orphan-marker"
            launched = root / "kicad-launched"
            board.write_bytes(Path("examples/multilayer.kicad_pcb").read_bytes())
            retained.write_bytes(b"retained-package-probe")

            fake_kicad = root / "fake-kicad-cli"
            fake_kicad.write_text(
                "#!/bin/sh\n"
                'root="${0%/*}"\n'
                'printf launched > "$root/kicad-launched"\n'
                '(sleep 2; printf orphan > "$root/orphan-marker") &\n'
                "wait\n",
                encoding="utf-8",
            )
            fake_kicad.chmod(0o700)

            delayed_exec = root / "delayed-exec.py"
            delayed_exec.write_text(
                "import os, sys, time\n"
                "time.sleep(2.5)\n"
                "os.execv(sys.argv[1], sys.argv[1:])\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ManufacturingReplayError,
                "manufacturing child (?:process failed|rejected the replay)",
            ):
                replay_manufacturing_package(
                    board,
                    retained,
                    [sys.executable, str(delayed_exec), binary],
                    kicad_cli=fake_kicad,
                    timeout_seconds=4.0,
                )
            self.assertTrue(launched.exists(), "real Rust path never launched KiCad")
            self.assertFalse(marker.exists(), "KiCad outlived the outer timeout")
            time.sleep(2.25)
            self.assertFalse(marker.exists(), "orphaned KiCad wrote after replay returned")

    def test_mutable_caller_pathlikes_are_frozen_exactly_once(self):
        class FlippingPath:
            def __init__(self, first: str, second: str) -> None:
                self.first = first
                self.second = second
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                return self.first if self.calls == 1 else self.second

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            project = root / "project.source"
            rules = root / "rules.source"
            profile = root / "non-default-profile.json"
            project.write_bytes(b"project")
            rules.write_bytes(b"rules")
            profile.write_bytes(b"profile")
            command = _write_fake_pcbex(root, package_raw)
            decoy = str(root / "must-not-be-observed")
            paths = {
                "board": FlippingPath(str(board), decoy),
                "package": FlippingPath(str(package), decoy),
                "project": FlippingPath(str(project), decoy),
                "rules": FlippingPath(str(rules), decoy),
                "profile": FlippingPath(str(profile), decoy),
                "kicad": FlippingPath("trusted-kicad-cli", decoy),
            }

            result = replay_manufacturing_package(
                paths["board"],
                paths["package"],
                command,
                kicad_cli=paths["kicad"],
                kicad_project=paths["project"],
                kicad_rules=paths["rules"],
                fab_profile=paths["profile"],
            )

            self.assertTrue(result["verified"])
            self.assertTrue(all(path.calls == 1 for path in paths.values()))
            invocation = json.loads((root / "invocation.json").read_text())
            self.assertIn("--kicad-cli=trusted-kicad-cli", invocation)
            self.assertNotIn(decoy, json.dumps(invocation))

    def test_deadline_expiring_during_result_assembly_cannot_return_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            command = _write_fake_pcbex(root, package_raw)
            now = [0.0]
            original = replay_module._profile_result

            def expire_during_result(**kwargs: object) -> dict[str, object]:
                result = original(**kwargs)
                now[0] = 121.0
                return result

            with mock.patch.object(
                replay_module,
                "_profile_result",
                side_effect=expire_during_result,
            ), self.assertRaisesRegex(ManufacturingReplayError, "deadline"):
                replay_manufacturing_package(
                    board,
                    package,
                    command,
                    timeout_seconds=120.0,
                    _clock=lambda: now[0],
                )

    def test_complete_injected_argv_is_count_byte_and_windows_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, _package_raw = self._sources(root)
            profile = root / "profile-with-bound-name.json"
            profile.write_bytes(b"profile")

            for command, kicad_cli in (
                (["pcbex", *(["x"] * 255)], "kicad-cli"),
                (["x" * replay_module.MAXIMUM_ARGUMENT_BYTES], "kicad-cli"),
                (["pcbex"], "k" * (replay_module.MAXIMUM_ARGUMENT_BYTES - 8)),
                (["pcbex", '"' * 16_380], "kicad-cli"),
            ):
                with self.subTest(
                    command_items=len(command), kicad_bytes=len(kicad_cli)
                ), mock.patch.object(replay_module, "run_bounded") as run:
                    with self.assertRaisesRegex(
                        ManufacturingReplayError, "child argv"
                    ):
                        replay_manufacturing_package(
                            board,
                            package,
                            command,
                            kicad_cli=kicad_cli,
                            fab_profile=profile,
                        )
                    run.assert_not_called()

            representative = [
                "pcbex",
                "fabricate",
                "board.kicad_pcb",
                "--outer-process-tree-supervised",
                "--output-dir=fresh",
                "--kicad-cli=kicad-cli",
                "--timeout-seconds=60",
                "--fab-profile=profile-with-bound-name.json",
            ]
            self.assertEqual(
                replay_module._validate_final_argv(representative), representative
            )
            self.assertEqual(
                representative.count("--outer-process-tree-supervised"), 1
            )

    def test_invalid_deadlines_commands_and_child_failures_are_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            board, package, package_raw = self._sources(root)
            for timeout in (True, 0, -1, float("inf"), 601):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(
                    ManufacturingReplayError, "timeout"
                ):
                    replay_manufacturing_package(
                        board, package, "pcbex", timeout_seconds=timeout
                    )
            with self.assertRaisesRegex(ManufacturingReplayError, "pcbex command"):
                replay_manufacturing_package(board, package, [])
            yielded = 0

            def oversized_command():
                nonlocal yielded
                while True:
                    yielded += 1
                    yield "wrapper"

            with self.assertRaisesRegex(ManufacturingReplayError, "pcbex command"):
                replay_manufacturing_package(board, package, oversized_command())
            self.assertEqual(yielded, replay_module.MAXIMUM_COMMAND_ARGUMENTS + 1)
            command = _write_fake_pcbex(root, package_raw, returncode=2)
            with self.assertRaisesRegex(ManufacturingReplayError, "child rejected"):
                replay_manufacturing_package(board, package, command)

    def test_cli_routes_all_options_and_prints_json(self):
        result = {
            "schema_version": 1,
            "verification_scope": "manufacturing-package-fresh-replay-v1",
            "verified": True,
        }
        stdout = io.StringIO()
        argv = [
            "pcbex-agent",
            "replay-manufacturing-package",
            "board.kicad_pcb",
            "retained.zip",
            "--pcbex",
            "native-pcbex",
            "--kicad-cli",
            "native-kicad-cli",
            "--kicad-project",
            "project.kicad_pro",
            "--kicad-rules",
            "rules.kicad_dru",
            "--fab-profile",
            "fab-special.json",
            "--timeout-seconds",
            "42.5",
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            cli, "replay_manufacturing_package", return_value=result
        ) as replay, redirect_stdout(stdout):
            cli.main()
        replay.assert_called_once()
        positional = replay.call_args.args
        kwargs = replay.call_args.kwargs
        self.assertEqual(positional[0], Path("board.kicad_pcb"))
        self.assertEqual(positional[1], Path("retained.zip"))
        self.assertEqual(positional[2], "native-pcbex")
        self.assertEqual(kwargs["kicad_cli"], "native-kicad-cli")
        self.assertEqual(kwargs["kicad_project"], Path("project.kicad_pro"))
        self.assertEqual(kwargs["kicad_rules"], Path("rules.kicad_dru"))
        self.assertEqual(kwargs["fab_profile"], Path("fab-special.json"))
        self.assertEqual(kwargs["timeout_seconds"], 42.5)
        self.assertEqual(json.loads(stdout.getvalue()), result)

        with mock.patch.object(
            sys,
            "argv",
            [
                "pcbex-agent",
                "replay-manufacturing-package",
                "board.kicad_pcb",
                "retained.zip",
                "--fab",
                "one",
                "--physical-profile",
                "two.json",
            ],
        ), self.assertRaises(SystemExit):
            cli.main()

    def test_schema_cli_stdout_and_no_clobber_output(self):
        stdout = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["pcbex-agent", "manufacturing-package-replay-result-schema"],
        ), redirect_stdout(stdout):
            cli.main()
        self.assertEqual(
            json.loads(stdout.getvalue()),
            manufacturing_package_replay_result_json_schema(),
        )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "schema.json"
            argv = [
                "pcbex-agent",
                "manufacturing-package-replay-result-schema",
                "--output",
                str(output),
            ]
            with mock.patch.object(sys, "argv", argv):
                cli.main()
            original = output.read_bytes()
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                cli.main()
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
