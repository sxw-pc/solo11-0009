"""Association graph: dataset-level join clusters over equality edges.

Once any column of dataset A equality-joins any column of dataset B, every
column of A is combinable with every column of B. Clusters are therefore
connected components of *datasets* linked by equality edges, and a cluster's
sensitive combination is the union of sensitive columns across its datasets.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Association, ColumnProfile


class UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, left: str, right: str) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left != root_right:
            self._parent[root_right] = root_left


@dataclass(frozen=True)
class LinkCluster:
    """Datasets connected by equality edges, i.e. one joinable combination."""

    cluster_id: str
    columns: tuple[ColumnProfile, ...]
    edges: tuple[Association, ...]

    @property
    def datasets(self) -> tuple[str, ...]:
        return tuple(sorted({column.ref.dataset_path for column in self.columns}))

    @property
    def join_key_columns(self) -> tuple[ColumnProfile, ...]:
        """Columns that actually carry an equality edge of this cluster."""
        endpoint_keys = {
            endpoint
            for edge in self.edges
            for endpoint in (edge.left.key, edge.right.key)
        }
        return tuple(
            column for column in self.columns if column.ref.key in endpoint_keys
        )

    def sensitive_type_scores(self, type_ignored=frozenset()) -> dict[str, float]:
        scores: dict[str, float] = {}
        for column in self.columns:
            if column.ignored or not column.sensitive_type:
                continue
            if column.sensitive_type in type_ignored:
                continue
            scores[column.sensitive_type] = max(
                scores.get(column.sensitive_type, 0.0), column.score
            )
        return scores


@dataclass(frozen=True)
class LinkGraph:
    clusters: tuple[LinkCluster, ...]
    equality_edges: tuple[Association, ...]
    semantic_edges: tuple[Association, ...]
    unclustered_datasets: int


def build_graph(
    profiles: dict[str, ColumnProfile],
    equality_edges: list[Association],
    semantic_edges: list[Association],
) -> LinkGraph:
    """Cluster datasets through equality edges; clusters span >= 2 datasets."""
    union_find = UnionFind()
    for profile in profiles.values():
        union_find.add(profile.ref.dataset_fingerprint)
    for edge in equality_edges:
        union_find.union(edge.left.dataset_fingerprint, edge.right.dataset_fingerprint)
    fingerprints_by_root: dict[str, set[str]] = {}
    for profile in profiles.values():
        fingerprints_by_root.setdefault(
            union_find.find(profile.ref.dataset_fingerprint), set()
        ).add(profile.ref.dataset_fingerprint)
    clusters: list[LinkCluster] = []
    for fingerprints in fingerprints_by_root.values():
        if len(fingerprints) < 2:
            continue
        columns = tuple(
            sorted(
                (
                    profile
                    for profile in profiles.values()
                    if profile.ref.dataset_fingerprint in fingerprints
                ),
                key=lambda profile: profile.ref.key,
            )
        )
        cluster_edges = tuple(
            sorted(
                (
                    edge
                    for edge in equality_edges
                    if edge.left.dataset_fingerprint in fingerprints
                    and edge.right.dataset_fingerprint in fingerprints
                ),
                key=lambda edge: (edge.left.key, edge.right.key),
            )
        )
        clusters.append(LinkCluster("", columns, cluster_edges))
    clusters.sort(key=lambda cluster: cluster.datasets)
    clusters = [
        LinkCluster(f"C{index}", cluster.columns, cluster.edges)
        for index, cluster in enumerate(clusters, start=1)
    ]
    all_datasets = {profile.ref.dataset_fingerprint for profile in profiles.values()}
    clustered = {
        column.ref.dataset_fingerprint for cluster in clusters for column in cluster.columns
    }
    return LinkGraph(
        clusters=tuple(clusters),
        equality_edges=tuple(equality_edges),
        semantic_edges=tuple(semantic_edges),
        unclustered_datasets=len(all_datasets - clustered),
    )
