"""Tests for the unified transformer registry, plugins, and resume identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineError, PipelineInterrupted
from maskline.pipeline.runner import execute_run, verify_resume_identities
from maskline.policies import PolicyError, load_policy
from maskline.transformers import (
    REGISTRY,
    ParamSpec,
    TransformContext,
    TransformError,
    TransformerRegistry,
    load_plugins,
    register_transformer,
)

PLUGIN = Path(__file__).resolve().parent / "fixtures" / "plugins" / "upper_case_plugin.py"


class _Dummy:
    def __init__(self, name: str = "dummy") -> None:
        self.name = name
        self.param_specs = ()

    def transform(self, value, params, context):
        return value


def test_builtins_keep_their_canonical_names():
    assert set(REGISTRY.names()) == {
        "mask", "hash", "generalize", "pseudonym", "nullify", "round"
    }


def test_duplicate_registration_raises_instead_of_overwriting():
    registry = TransformerRegistry()
    original = _Dummy("dup")
    registry.register(original)
    assert registry.get("dup") is original
    replacement = _Dummy("dup")
    with pytest.raises(TransformError, match="already registered"):
        registry.register(replacement)
    # The original implementation must still be the one served.
    assert registry.get("dup") is original


def test_class_and_instance_registration_both_work():
    registry = TransformerRegistry()

    class ClassStyle:
        name = "class_style"
        param_specs = ()

        def transform(self, value, params, context):
            return value

    registry.register(ClassStyle)
    assert isinstance(registry.get("class_style"), ClassStyle)
    registry.register(_Dummy("instance_style"))
    assert registry.get("instance_style").name == "instance_style"


def test_malformed_transformer_is_rejected():
    registry = TransformerRegistry()
    with pytest.raises(TransformError):
        registry.register(object())


def test_implementation_id_tracks_schema_and_version():
    from maskline.transformers.base import implementation_id

    class Static:
        name = "static"
        version = 1
        param_specs = (ParamSpec("width", "int", default=10, minimum=1),)

        def transform(self, value, params, context):
            return value

    baseline = implementation_id(Static())

    # Bumping the declared version changes the identity...
    Static.version = 2
    assert implementation_id(Static()) != baseline
    Static.version = 1
    assert implementation_id(Static()) == baseline

    # ...and so does changing the parameter schema.
    original_specs = Static.param_specs
    Static.param_specs = (ParamSpec("width", "int", default=20, minimum=1),)
    assert implementation_id(Static()) != baseline
    Static.param_specs = original_specs
    assert implementation_id(Static()) == baseline


def test_implementation_id_tracks_source_file_changes(tmp_path):
    """A code edit to a plugin file changes its implementation id."""
    from maskline.transformers.base import implementation_id

    plugin = tmp_path / "source_plugin.py"

    def write(body_line: str) -> None:
        # Plain class on purpose: this test only needs the source digest, not
        # global registration, so no @register_transformer side effects.
        plugin.write_text(
            "class SourcePlugin:\n"
            "    name = 'source_plugin_tmp'\n"
            "    version = 1\n"
            "    param_specs = ()\n"
            "    def transform(self, value, params, context):\n"
            f"        {body_line}\n",
            encoding="utf-8",
        )

    import importlib.util

    def load_class():
        # A unique module name avoids touching sys.modules cache; the class's
        # own source file is still the plugin path used by the id digest.
        spec = importlib.util.spec_from_file_location(
            f"source_probe_{plugin.stat().st_mtime_ns}", plugin
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.SourcePlugin

    write("return value")
    first_class = load_class()
    first = implementation_id(first_class())
    write("return None  # changed implementation")
    second_class = load_class()
    second = implementation_id(second_class())
    assert second != first
    # Unrelated classes are unaffected by the plugin file change.
    assert implementation_id(_Dummy("x")) == implementation_id(_Dummy("x"))


def test_plugin_file_registers_without_package_edits():
    # The plugin name must not exist before loading.
    assert not REGISTRY.has("upper_case")
    contributed = load_plugins(PLUGIN)
    try:
        assert contributed == ["upper_case"]
        assert REGISTRY.has("upper_case")
        context = TransformContext()
        assert REGISTRY.transform("upper_case", "abc", {}, context) == "ABC"
        assert (
            REGISTRY.transform("upper_case", "abc", {"suffix": "!"}, context)
            == "ABC!"
        )
        # Same registry mechanisms as built-ins: null safety and validation.
        assert REGISTRY.transform("upper_case", None, {}, context) is None
        with pytest.raises(TransformError):
            REGISTRY.validate_params("upper_case", {"suffix": 3})
        # Loading the same plugin again is a no-op, not a duplicate error.
        assert load_plugins(PLUGIN) == []
    finally:
        # Restore the global registry for the rest of the suite.
        REGISTRY._items.pop("upper_case", None)
        REGISTRY._ids.pop("upper_case", None)


def test_plugin_directory_and_missing_path_handling(tmp_path):
    assert load_plugins(None) == []
    with pytest.raises(TransformError, match="does not exist"):
        load_plugins(tmp_path / "no-such-plugin.py")
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "one.py").write_text(PLUGIN.read_text(encoding="utf-8"), encoding="utf-8")
    (plugin_dir / "ignored.txt").write_text("not python", encoding="utf-8")
    try:
        assert load_plugins(plugin_dir) == ["upper_case"]
    finally:
        REGISTRY._items.pop("upper_case", None)
        REGISTRY._ids.pop("upper_case", None)


def test_policy_referencing_plugin_type_loads_after_plugin_is_available(
    tmp_path, make_policy
):
    policy_text = """
    version: 1
    name: plugin-policy
    datasets:
      - path: demo.sqlite
        tables:
          customers:
            columns:
              phone: {transformer: upper_case}
    """
    # Before the plugin is loaded the type is rejected at policy load time.
    with pytest.raises(PolicyError, match="unknown transformer"):
        make_policy(policy_text)
    load_plugins(PLUGIN)
    try:
        policy = make_policy(policy_text)
        detail = policy.datasets[0].tables["customers"].columns["phone"]
        assert detail.transformer == "upper_case"
        with pytest.raises(PolicyError, match="unknown transformer parameter"):
            make_policy(
                """
                version: 1
                name: plugin-policy-bad
                datasets:
                  - path: demo.sqlite
                    tables:
                      customers:
                        columns:
                          phone:
                            transformer: upper_case
                            params: {bogus: 1}
                """
            )
    finally:
        REGISTRY._items.pop("upper_case", None)
        REGISTRY._ids.pop("upper_case", None)


def test_unknown_transformer_fails_at_planning_without_target_residue(
    tmp_path, inventories, make_policy
):
    from maskline.config import Paths

    # A policy can only be built while the type is registered; the realistic
    # failure (plugin missing on the next run) then removes it again.
    REGISTRY.register(_Dummy("ghost_transformer"))
    try:
        policy = make_policy(
            """
            version: 1
            name: ghost-policy
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone: {transformer: ghost_transformer}
            """
        )
    finally:
        REGISTRY._items.pop("ghost_transformer", None)
        REGISTRY._ids.pop("ghost_transformer", None)

    workspace = tmp_path / "workspace"
    paths = Paths.for_workspace(workspace)
    # The runner's planning gate rejects the unregistered type...
    with pytest.raises(PipelineError, match="unknown transformer"):
        execute_run(inventories["sqlite"], policy, paths)
    # ...and nothing was created: no runtime dir, no target database, no
    # checkpoint database. The source dataset must be untouched as well.
    assert not workspace.exists()
    assert not paths.out_dir.exists()
    assert not paths.checkpoint_db.exists()


def test_policy_load_itself_rejects_unregistered_type_without_io(tmp_path):
    policy_path = tmp_path / "bad.yaml"
    policy_path.write_text(
        "version: 1\n"
        "name: bad\n"
        "datasets:\n"
        "  - path: demo.sqlite\n"
        "    tables:\n"
        "      customers:\n"
        "        columns:\n"
        "          phone: {transformer: does_not_exist}\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="unknown transformer"):
        load_policy(policy_path)


def test_run_records_transformer_identities_in_checkpoint_and_manifest(
    workspace, inventories, secret_store
):
    from maskline.policies import load_policy

    example = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
    policy = load_policy(example)
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    with CheckpointStore(workspace.checkpoint_db) as store:
        record = store.get_run(result.run_id)
    assert record is not None
    assert set(record.transformer_identities) == {
        "mask", "hash", "generalize", "pseudonym", "nullify", "round"
    }
    for name, stored_id in record.transformer_identities.items():
        assert stored_id == REGISTRY.implementation_id(name)
    manifest = json.loads(
        (workspace.manifest_dir / f"{inventories['sqlite'].fingerprint[:16]}.json")
        .read_text(encoding="utf-8")
    )
    assert manifest["transformer_identities"] == record.transformer_identities


def test_resume_rejected_when_transformer_implementation_changed(
    tmp_path, inventories, secret_store
):
    from maskline.config import Paths
    from maskline.policies import load_policy

    example = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
    policy = load_policy(example)
    paths = Paths.for_workspace(tmp_path / "interrupted")
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    target_before = list(Path(paths.out_dir).glob("*.sqlite"))
    assert target_before  # the interrupted run did create a target

    with CheckpointStore(paths.checkpoint_db) as store:
        record = store.get_run(run_id)
        tampered = dict(record.transformer_identities)
        tampered["mask"] = "0" * 64
        store.conn.execute(
            "UPDATE runs SET transformer_identities_json = ? WHERE run_id = ?",
            (json.dumps(tampered, sort_keys=True), run_id),
        )
        store.conn.commit()
        stale = store.get_run(run_id)

    with pytest.raises(PipelineError, match="implementation changed"):
        verify_resume_identities(stale)
    with pytest.raises(PipelineError, match="implementation changed"):
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, resume_run_id=run_id,
        )
    # The target must be untouched after the refused resume.
    assert list(Path(paths.out_dir).glob("*.sqlite")) == target_before


def test_resume_rejected_when_transformer_no_longer_registered(
    tmp_path, inventories, secret_store
):
    from maskline.config import Paths
    from maskline.policies import load_policy

    example = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
    policy = load_policy(example)
    paths = Paths.for_workspace(tmp_path / "interrupted-missing")
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    with CheckpointStore(paths.checkpoint_db) as store:
        record = store.get_run(run_id)
        tampered = dict(record.transformer_identities)
        tampered["vanished"] = tampered.pop("mask")
        store.conn.execute(
            "UPDATE runs SET transformer_identities_json = ? WHERE run_id = ?",
            (json.dumps(tampered, sort_keys=True), run_id),
        )
        store.conn.commit()
        stale = store.get_run(run_id)

    with pytest.raises(PipelineError, match="no longer registered"):
        verify_resume_identities(stale)


def test_resume_accepts_identical_implementations(tmp_path, inventories, secret_store):
    from maskline.config import Paths
    from maskline.policies import load_policy

    example = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
    policy = load_policy(example)
    paths = Paths.for_workspace(tmp_path / "resume-ok")
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    with CheckpointStore(paths.checkpoint_db) as store:
        verify_resume_identities(store.get_run(run_id))
    resumed = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=secret_store, resume_run_id=run_id,
    )
    assert resumed.run_id == run_id


def test_decorator_function_registers_on_global_registry():
    @register_transformer
    class Decorated:
        name = "decorated_tmp"
        param_specs = ()

        def transform(self, value, params, context):
            return value

    try:
        assert REGISTRY.has("decorated_tmp")
        with pytest.raises(TransformError, match="already registered"):
            REGISTRY.register(Decorated)
    finally:
        REGISTRY._items.pop("decorated_tmp", None)
        REGISTRY._ids.pop("decorated_tmp", None)
