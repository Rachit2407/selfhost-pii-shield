"""Relational database connector preserving referential integrity across foreign keys."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import re
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine

from app.engine.deterministic import AnonymizeMode
from app.engine.pipeline import PIIShieldPipeline


# Heuristic column-name -> entity type mapping for zero-config DB inspection.
_COLUMN_HEURISTICS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|_)e?mail(_|$)", re.I), "EMAIL_ADDRESS"),
    (re.compile(r"(^|_)(phone|mobile|contact_no|tel)(_|$)", re.I), "PHONE_NUMBER"),
    (re.compile(r"(^|_)(pan|pan_no|pan_number)(_|$)", re.I), "IN_PAN"),
    (re.compile(r"(^|_)(aadhaar|aadhar|uidai)(_|$)", re.I), "IN_AADHAAR"),
    (re.compile(r"(^|_)(upi|upi_id|vpa)(_|$)", re.I), "IN_UPI"),
    (re.compile(r"(^|_)(ssn|social_security)(_|$)", re.I), "US_SSN"),
    (re.compile(r"(^|_)(ip|ip_address|client_ip)(_|$)", re.I), "IP_ADDRESS"),
    (re.compile(r"(^|_)(api_key|secret|access_token|jwt)(_|$)", re.I), "SECRET_TOKEN"),
    (re.compile(r"(^|_)(full_name|first_name|last_name|customer_name|user_name)(_|$)", re.I), "PERSON"),
    (re.compile(r"^name$", re.I), "PERSON"),
    (re.compile(r"(^|_)(city|address|street|location)(_|$)", re.I), "LOCATION"),
    (re.compile(r"(^|_)(notes|description|body|message|comment|summary|transcript|prompt)(_|$)", re.I), "FREE_TEXT"),
)

_NON_PII_NAME_EXCLUSIONS = re.compile(
    r"(product|item|plan|status|role|table|file|category|tenant|app|service)_name$", re.I
)


class _DisjointSet:
    """Union-Find structure to group connected PK/FK columns into equivalence classes."""

    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(self, item: tuple[str, str]) -> tuple[str, str]:
        if item not in self.parent:
            self.parent[item] = item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: tuple[str, str], b: tuple[str, str]) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Prefer deterministic lexicographical root for stable reporting.
            if ra < rb:
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb


@dataclass
class ForeignKeyLink:
    """Directed FK relationship from child column(s) to parent column(s)."""

    child_table: str
    child_columns: list[str]
    parent_table: str
    parent_columns: list[str]


@dataclass
class TableInspection:
    """Introspected metadata for a single table."""

    name: str
    row_count: int
    primary_keys: list[str]
    unique_columns: list[str]
    columns: list[str]
    suggested_rules: dict[str, str]


@dataclass
class DatabaseInspectionReport:
    """Full schema inspection output including topological order & FK groups."""

    dialect: str
    topological_order: list[str]
    tables: list[TableInspection]
    foreign_keys: list[ForeignKeyLink]
    fk_equivalence_groups: dict[str, list[str]]


@dataclass
class DatabaseAnonymizeReport:
    """Execution summary after anonymizing source DB -> target DB."""

    source_dialect: str
    target_dialect: str
    mode: AnonymizeMode
    tables_processed: list[str]
    rows_copied: dict[str, int]
    fields_anonymized: dict[str, int]
    fk_groups_preserved: int
    applied_rules: dict[str, str] = field(default_factory=dict)


def _enable_sqlite_fks(engine: Engine) -> None:
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()


def _infer_column_rule(table_name: str, col_name: str, is_pk: bool, col_type_str: str) -> str | None:
    """Infer PII entity type from column name while avoiding false positives on surrogate IDs."""
    if _NON_PII_NAME_EXCLUSIONS.search(col_name):
        return None
    for pattern, entity in _COLUMN_HEURISTICS:
        if pattern.search(col_name):
            return entity
    # Avoid treating integer auto-increment PKs as PII by default.
    if is_pk and ("INT" in col_type_str.upper()):
        return None
    return None


def _topological_sort(tables: list[str], fk_links: list[ForeignKeyLink]) -> list[str]:
    """Order tables from parents to children so FK constraints hold on insert."""
    in_degree: dict[str, int] = {t: 0 for t in tables}
    children: dict[str, set[str]] = defaultdict(set)

    for fk in fk_links:
        if fk.parent_table == fk.child_table:
            continue  # Self-referencing FK handled within table pass.
        if fk.child_table not in children[fk.parent_table]:
            children[fk.parent_table].add(fk.child_table)
            in_degree[fk.child_table] += 1

    queue = deque(sorted(t for t, deg in in_degree.items() if deg == 0))
    order: list[str] = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for child in sorted(children[node]):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    # Append any cyclic tables deterministically if circular FKs exist.
    remaining = [t for t in sorted(tables) if t not in order]
    order.extend(remaining)
    return order


def inspect_database(
    dsn: str,
    column_rules: dict[str, str] | None = None,
) -> DatabaseInspectionReport:
    """Introspect schema, FK graph, topological order, and suggested PII column rules."""
    engine = create_engine(dsn)
    inspector = inspect(engine)
    table_names = sorted(inspector.get_table_names())

    dsu = _DisjointSet()
    fk_links: list[ForeignKeyLink] = []
    raw_rules: dict[tuple[str, str], str] = {}
    table_meta: dict[str, dict[str, Any]] = {}

    with engine.connect() as conn:
        for t_name in table_names:
            pk_info = inspector.get_pk_constraint(t_name)
            pks = list(pk_info.get("constrained_columns") or [])
            unique_cols: set[str] = set(pks)
            for uc in inspector.get_unique_constraints(t_name):
                unique_cols.update(uc.get("column_names") or [])
            for idx in inspector.get_indexes(t_name):
                if idx.get("unique"):
                    unique_cols.update(idx.get("column_names") or [])

            cols_info = inspector.get_columns(t_name)
            col_names = [c["name"] for c in cols_info]

            for col in cols_info:
                c_name = col["name"]
                dsu.find((t_name, c_name))
                explicit_key = f"{t_name}.{c_name}"
                if column_rules and explicit_key in column_rules:
                    raw_rules[(t_name, c_name)] = column_rules[explicit_key]
                else:
                    inferred = _infer_column_rule(
                        t_name, c_name, c_name in pks, str(col.get("type", ""))
                    )
                    if inferred:
                        raw_rules[(t_name, c_name)] = inferred

            for fk in inspector.get_foreign_keys(t_name):
                ref_table = fk.get("referred_table")
                ref_cols = fk.get("referred_columns") or []
                local_cols = fk.get("constrained_columns") or []
                if not ref_table or len(ref_cols) != len(local_cols):
                    continue
                fk_links.append(
                    ForeignKeyLink(
                        child_table=t_name,
                        child_columns=list(local_cols),
                        parent_table=ref_table,
                        parent_columns=list(ref_cols),
                    )
                )
                for l_col, r_col in zip(local_cols, ref_cols):
                    dsu.union((t_name, l_col), (ref_table, r_col))

            row_count = conn.execute(text(f'SELECT COUNT(*) FROM "{t_name}"')).scalar() or 0
            table_meta[t_name] = {
                "row_count": int(row_count),
                "pks": pks,
                "unique_cols": sorted(unique_cols),
                "columns": col_names,
            }

    # Propagate PII entity rules across connected FK equivalence classes so joins match 100%.
    groups: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for node in list(dsu.parent.keys()):
        groups[dsu.find(node)].append(node)

    propagated_rules: dict[tuple[str, str], str] = dict(raw_rules)
    fk_group_summary: dict[str, list[str]] = {}
    for root, members in groups.items():
        if len(members) > 1:
            fk_group_summary[f"{root[0]}.{root[1]}"] = sorted(
                f"{t}.{c}" for t, c in members
            )
            group_rule = next((raw_rules[m] for m in members if m in raw_rules), None)
            if group_rule:
                for m in members:
                    propagated_rules[m] = group_rule

    topo_order = _topological_sort(table_names, fk_links)
    inspections: list[TableInspection] = []
    for t_name in topo_order:
        meta = table_meta[t_name]
        t_rules = {
            c: propagated_rules[(t_name, c)]
            for c in meta["columns"]
            if (t_name, c) in propagated_rules
        }
        inspections.append(
            TableInspection(
                name=t_name,
                row_count=meta["row_count"],
                primary_keys=meta["pks"],
                unique_columns=meta["unique_cols"],
                columns=meta["columns"],
                suggested_rules=t_rules,
            )
        )

    engine.dispose()
    return DatabaseInspectionReport(
        dialect=engine.dialect.name,
        topological_order=topo_order,
        tables=inspections,
        foreign_keys=fk_links,
        fk_equivalence_groups=fk_group_summary,
    )


def _order_self_referencing_rows(
    rows: list[dict[str, Any]],
    self_fks: list[ForeignKeyLink],
) -> list[dict[str, Any]]:
    """Order rows within a self-referencing table so referenced parent rows insert first."""
    if not self_fks or len(rows) <= 1:
        return rows

    ordered: list[dict[str, Any]] = []
    remaining = list(rows)
    inserted_keys: dict[tuple[str, ...], set[tuple[Any, ...]]] = defaultdict(set)

    # Iteratively emit rows whose self-FK parent keys are NULL or already emitted.
    while remaining:
        progressed = False
        next_remaining: list[dict[str, Any]] = []
        for row in remaining:
            ready = True
            for fk in self_fks:
                child_vals = tuple(row.get(c) for c in fk.child_columns)
                if all(v is None for v in child_vals):
                    continue
                parent_cols_key = tuple(fk.parent_columns)
                if child_vals not in inserted_keys[parent_cols_key]:
                    ready = False
                    break
            if ready:
                ordered.append(row)
                for fk in self_fks:
                    parent_cols_key = tuple(fk.parent_columns)
                    inserted_keys[parent_cols_key].add(tuple(row.get(c) for c in fk.parent_columns))
                progressed = True
            else:
                next_remaining.append(row)
        if not progressed:
            # Break potential row-level cycles deterministically.
            ordered.extend(next_remaining)
            break
        remaining = next_remaining

    return ordered


def _anonymize_row(
    row: Any,
    t_name: str,
    t_rules: dict[str, str],
    pipeline: PIIShieldPipeline,
    mode: AnonymizeMode,
    dsu: _DisjointSet,
    unique_sets: dict[tuple[str, str], bool],
    eq_raw_to_synth: dict[tuple[str, str], dict[str, str]],
    eq_used_synth: dict[tuple[str, str], set[str]],
    fields_anonymized: dict[str, int],
) -> dict[str, Any]:
    """Anonymize a single row's PII columns using FK-equivalence-class caches."""
    new_row = dict(row)
    for col_name, rule in t_rules.items():
        val = new_row.get(col_name)
        if val is None:
            continue
        str_val = str(val)
        if not str_val.strip():
            continue

        if rule == "FREE_TEXT":
            scrubbed = pipeline.scrub_text(str_val, mode=mode)
            new_row[col_name] = scrubbed.scrubbed_text
            fields_anonymized["FREE_TEXT"] += scrubbed.findings_count
            continue

        eq_root = dsu.find((t_name, col_name))
        cache = eq_raw_to_synth[eq_root]
        if str_val in cache:
            synth_val = cache[str_val]
        else:
            used = eq_used_synth[eq_root]
            require_unique = unique_sets[eq_root]
            collision_idx = 0
            while True:
                candidate = pipeline.anonymizer.anonymize(
                    entity_type=rule,
                    raw_value=str_val,
                    mode=mode,
                    collision_index=collision_idx,
                )
                if not require_unique or candidate not in used:
                    synth_val = candidate
                    break
                collision_idx += 1
            cache[str_val] = synth_val
            used.add(synth_val)

        if isinstance(val, int) and rule == "SURROGATE_ID":
            new_row[col_name] = int(synth_val)
        else:
            new_row[col_name] = synth_val
        fields_anonymized[rule] += 1

    return new_row


def anonymize_database(
    source_dsn: str,
    target_dsn: str,
    pipeline: PIIShieldPipeline,
    mode: AnonymizeMode = "synthetic",
    column_rules: dict[str, str] | None = None,
    truncate_target: bool = True,
    batch_size: int = 5000,
) -> DatabaseAnonymizeReport:
    """Clone schema and copy anonymized rows from source_dsn to target_dsn preserving FKs."""
    if source_dsn == target_dsn:
        raise ValueError("Refusing in-place mutation: source_dsn and target_dsn must differ.")
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1.")

    inspection = inspect_database(source_dsn, column_rules=column_rules)

    src_engine = create_engine(source_dsn)
    tgt_engine = create_engine(target_dsn)
    _enable_sqlite_fks(src_engine)
    _enable_sqlite_fks(tgt_engine)

    src_meta = MetaData()
    src_meta.reflect(bind=src_engine)

    if truncate_target:
        src_meta.drop_all(bind=tgt_engine, checkfirst=True)
    src_meta.create_all(bind=tgt_engine, checkfirst=True)

    # Build lookup from (table, col) -> equivalence group root & whether uniqueness is needed.
    dsu = _DisjointSet()
    for t_info in inspection.tables:
        for col in t_info.columns:
            dsu.find((t_info.name, col))
    for fk in inspection.foreign_keys:
        for lc, rc in zip(fk.child_columns, fk.parent_columns):
            dsu.union((fk.child_table, lc), (fk.parent_table, rc))

    unique_sets: dict[tuple[str, str], bool] = defaultdict(bool)
    applied_rules: dict[str, str] = {}
    for t_info in inspection.tables:
        unique_cols = set(t_info.unique_columns)
        for col, rule in t_info.suggested_rules.items():
            applied_rules[f"{t_info.name}.{col}"] = rule
            if col in unique_cols:
                unique_sets[dsu.find((t_info.name, col))] = True

    # Per-equivalence-class caches guarantee identical FK values and zero UNIQUE collisions.
    eq_raw_to_synth: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    eq_used_synth: dict[tuple[str, str], set[str]] = defaultdict(set)

    rows_copied: dict[str, int] = {}
    fields_anonymized: dict[str, int] = defaultdict(int)

    with src_engine.connect() as src_conn, tgt_engine.begin() as tgt_conn:
        for t_name in inspection.topological_order:
            table_obj: Table = src_meta.tables[t_name]
            t_info = next(t for t in inspection.tables if t.name == t_name)
            t_rules = t_info.suggested_rules

            self_fks = [
                fk
                for fk in inspection.foreign_keys
                if fk.child_table == t_name and fk.parent_table == t_name
            ]
            row_total = 0

            if self_fks:
                rows = src_conn.execute(select(table_obj)).mappings().all()
                payloads = [
                    _anonymize_row(
                        row,
                        t_name,
                        t_rules,
                        pipeline,
                        mode,
                        dsu,
                        unique_sets,
                        eq_raw_to_synth,
                        eq_used_synth,
                        fields_anonymized,
                    )
                    for row in rows
                ]
                if payloads:
                    ordered_payloads = _order_self_referencing_rows(payloads, self_fks)
                    for item in ordered_payloads:
                        tgt_conn.execute(table_obj.insert(), item)
                row_total = len(payloads)
            else:
                result = src_conn.execute(
                    select(table_obj).execution_options(stream_results=True)
                ).mappings()
                while True:
                    chunk = result.fetchmany(batch_size)
                    if not chunk:
                        break
                    payloads = [
                        _anonymize_row(
                            row,
                            t_name,
                            t_rules,
                            pipeline,
                            mode,
                            dsu,
                            unique_sets,
                            eq_raw_to_synth,
                            eq_used_synth,
                            fields_anonymized,
                        )
                        for row in chunk
                    ]
                    tgt_conn.execute(table_obj.insert(), payloads)
                    row_total += len(payloads)

            rows_copied[t_name] = row_total

    src_dialect = inspection.dialect
    tgt_dialect = tgt_engine.dialect.name
    src_engine.dispose()
    tgt_engine.dispose()

    return DatabaseAnonymizeReport(
        source_dialect=src_dialect,
        target_dialect=tgt_dialect,
        mode=mode,
        tables_processed=inspection.topological_order,
        rows_copied=rows_copied,
        fields_anonymized=dict(fields_anonymized),
        fk_groups_preserved=len(inspection.fk_equivalence_groups),
        applied_rules=applied_rules,
    )
