"""GraphOps log parser — raw telemetry in, NetworkX DiGraph out.

Accepts CSV or JSON logs shaped like Sysmon / Windows Security events and
dynamically synthesizes nodes (hosts, users, IPs, processes) and timestamped
edges ONLY from the log data.  Nothing is hardcoded: node IDs derive from
log fields, edge types from event IDs.

Supported inputs
----------------
CSV columns (case-insensitive, extras ignored):
    timestamp, event_id, computer, src_host, dst_host, host,
    src_ip, dst_ip, ip, user, username, target_user,
    logon_type, process, image, parent_image, command_line,
    destination_port, share, tier, role

JSON: a list of dicts with the same keys (any casing).

Event mapping
-------------
- Sysmon Event ID 1 (ProcessCreate) -> host --spawned--> process
- Sysmon Event ID 3 (NetworkConnect) -> host --connected--> ip (timestamps kept)
- Windows Event ID 4624 (Logon)      -> user --logon--> host
  (Logon Type 3 = network logon; stored on the edge as ``logon_type``)
- Generic rows with a source and destination -> edge with ``etype`` taken
  from ``event_id``/``action`` or ``"generic"``.

Graph contract (matches the rest of GraphOps):
- node id: ``f"{etype}:{eid}"`` with etype in {host, user, ip, process}
- edges carry ``etype``, ``ts`` (earliest timestamp) and ``timestamps``
  (sorted list of every observed timestamp on that pair) plus the raw
  fields that produced them (logon_type, share, image, ...).
- DiGraph is used (single edge per pair); parallel connections are folded
  into ``timestamps`` so beaconing math still sees every event.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import networkx as nx


# ---------------------------------------------------------------------------
# field normalization
# ---------------------------------------------------------------------------

_FIELD_ALIASES = {
    "timestamp": {"timestamp", "time", "utctime", "utc_time", "datetime", "@timestamp"},
    "event_id": {"event_id", "eventid", "event-id"},
    "computer": {"computer", "computername", "host", "hostname"},
    "src_host": {"src_host", "source_host", "workstation", "workstation_name"},
    "dst_host": {"dst_host", "dest_host", "target_host"},
    "src_ip": {"src_ip", "source_ip", "ipaddress"},
    "dst_ip": {"dst_ip", "dest_ip", "destination_ip", "ip"},
    "user": {"user", "username", "account", "target_user", "targetusername", "subject_user"},
    "src_user": {"src_user", "source_user"},
    "logon_type": {"logon_type", "logontype"},
    "image": {"image", "process", "process_name", "imagename"},
    "parent_image": {"parent_image", "parentimage", "parent_process"},
    "command_line": {"command_line", "commandline"},
    "dst_port": {"destination_port", "dest_port", "dst_port", "port"},
    "share": {"share", "share_name", "sharename"},
    "tier": {"tier", "asset_tier"},
    "role": {"role", "asset_role"},
    "action": {"action", "event_type"},
}

_NORM_FIELDS = tuple(_FIELD_ALIASES)


def _normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Map arbitrary-cased keys onto the canonical field names."""
    lowered = {}
    for k, v in row.items():
        if k is None:
            continue
        lowered[str(k).strip().lower()] = v
    out: Dict[str, Any] = {}
    for canon, aliases in _FIELD_ALIASES.items():
        for a in aliases:
            if a in lowered and lowered[a] not in (None, ""):
                out[canon] = lowered[a]
                break
    return out


def _parse_ts(value: Any) -> Optional[float]:
    """Parse a timestamp value to epoch seconds. Returns None when unparseable."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        f = float(value)
        # treat large ints as epoch seconds; millis get normalized
        return f / 1000.0 if f > 1e12 else f
    s = str(value).strip()
    try:
        return float(s)
    except ValueError:
        pass
    # ISO-8601 / common datetime strings (Sysmon UtcTime etc.)
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s.split("+")[0].rstrip("Z"), fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def _clean_host(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower().split(".")[0]
    s = s.replace("\\\\", "").lstrip("\\")
    return s or None


def _clean_user(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower()
    for sep in ("\\", "@"):
        if sep in s:
            s = s.split(sep)[-1]
    if s in {"", "-", "anonymous", "null", "unknown"}:
        return None
    return s


def _clean_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower().rstrip(".")
    if s in {"", "-", "::", "0.0.0.0"}:
        return None
    # strip trailing port if it looks like ip:port
    if s.count(":") == 1 and "." in s:
        host, _, port = s.partition(":")
        if port.isdigit():
            s = host
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def _is_external_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def _proc_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower().replace("/", "\\")
    name = s.split("\\")[-1]
    return name or None


# ---------------------------------------------------------------------------
# ingestion: CSV / JSON -> normalized events
# ---------------------------------------------------------------------------

def parse_csv(text: str) -> List[Dict[str, Any]]:
    """Parse CSV log text into normalized event dicts."""
    events: List[Dict[str, Any]] = []
    if not text or not text.strip():
        return events
    reader = csv.DictReader(io.StringIO(text.strip()))
    for row in reader:
        norm = _normalize_row(row)
        if norm:
            events.append(norm)
    return events


def parse_json(data: Any) -> List[Dict[str, Any]]:
    """Parse a JSON string (or already-decoded list/dict) into normalized events."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    events = []
    for row in data:
        if isinstance(row, dict):
            norm = _normalize_row(row)
            if norm:
                events.append(norm)
    return events


def ingest(raw: Any, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
    """Auto-detect CSV vs JSON and return normalized events."""
    if fmt == "csv" or (fmt is None and isinstance(raw, str)
                        and "\n" in raw.strip() and "," in raw.strip().split("\n", 1)[0]):
        return parse_csv(raw)
    return parse_json(raw)


# ---------------------------------------------------------------------------
# graph construction
# ---------------------------------------------------------------------------

def _add_node(G: nx.DiGraph, etype: str, eid: str, **attrs: Any) -> str:
    nid = f"{etype}:{eid}"
    if G.has_node(nid):
        node = G.nodes[nid]
        for k, v in attrs.items():
            if v is not None and k not in node:
                node[k] = v
    else:
        payload = {"etype": etype, "eid": eid}
        payload.update({k: v for k, v in attrs.items() if v is not None})
        G.add_node(nid, **payload)
    return nid


def _add_edge(G: nx.DiGraph, src: str, dst: str, etype: str,
              ts: Optional[float], **attrs: Any) -> None:
    if G.has_edge(src, dst):
        data = G.edges[src, dst]
        if ts is not None:
            data.setdefault("timestamps", []).append(ts)
            data["timestamps"] = sorted(set(data["timestamps"]))
            data["ts"] = min(data["timestamps"])
        for k, v in attrs.items():
            if v is not None and k not in data:
                data[k] = v
        # keep the most specific etype seen
        if etype and etype != "generic" and data.get("etype") == "generic":
            data["etype"] = etype
    else:
        payload: Dict[str, Any] = {"etype": etype}
        payload["ts"] = ts
        payload["timestamps"] = sorted({ts}) if ts is not None else []
        payload.update({k: v for k, v in attrs.items() if v is not None})
        G.add_edge(src, dst, **payload)


def _event_id(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_id", "")).strip()


def build_graph(events: Iterable[Dict[str, Any]]) -> nx.DiGraph:
    """Build a timestamped DiGraph purely from parsed log events.

    No hardcoded hosts, users, IPs or attack paths: every node and edge is
    synthesized from fields present in the telemetry.
    """
    G = nx.DiGraph()
    for ev in events:
        try:
            _ingest_event(G, ev)
        except Exception:
            continue  # a malformed row never kills the build
    return G


def _ingest_event(G: nx.DiGraph, ev: Dict[str, Any]) -> None:
    ts = _parse_ts(ev.get("timestamp"))
    eid = _event_id(ev)
    host = _clean_host(ev.get("computer"))
    src_host = _clean_host(ev.get("src_host"))
    dst_host = _clean_host(ev.get("dst_host"))
    user = _clean_user(ev.get("user"))
    src_user = _clean_user(ev.get("src_user"))
    src_ip = _clean_ip(ev.get("src_ip"))
    dst_ip = _clean_ip(ev.get("dst_ip"))
    image = _proc_name(ev.get("image"))
    parent_image = _proc_name(ev.get("parent_image"))
    cmdline = ev.get("command_line")
    cmdline = str(cmdline).strip() if cmdline not in (None, "") else None
    dst_port = ev.get("dst_port")
    try:
        dst_port = int(str(dst_port).strip()) if dst_port not in (None, "") else None
    except (ValueError, TypeError):
        dst_port = None
    share = ev.get("share")
    share = str(share).strip().upper() if share not in (None, "") else None
    logon_type = ev.get("logon_type")
    try:
        logon_type = int(str(logon_type).strip()) if logon_type not in (None, "") else None
    except (ValueError, TypeError):
        logon_type = None
    tier = ev.get("tier")
    role = ev.get("role")
    role = str(role).strip().lower() if role not in (None, "") else None

    host_attrs = {}
    if tier not in (None, ""):
        try:
            host_attrs["tier"] = int(str(tier).strip())
        except (ValueError, TypeError):
            pass
    if role:
        host_attrs["role"] = role

    # --- Sysmon 1: process creation -------------------------------------
    if eid == "1":
        if not host or not image:
            return
        h = _add_node(G, "host", host, **host_attrs)
        p = _add_node(G, "process", f"{host}:{image}")
        _add_edge(G, h, p, "spawned", ts, image=image,
                  parent_image=parent_image, command_line=cmdline, user=user)
        if user:
            u = _add_node(G, "user", user)
            _add_edge(G, u, p, "executed", ts)
        return

    # --- Sysmon 3: network connection ------------------------------------
    if eid == "3":
        if not host or not dst_ip:
            return
        h = _add_node(G, "host", host, **host_attrs)
        ip_node = _add_node(G, "ip", dst_ip, external=_is_external_ip(dst_ip))
        _add_edge(G, h, ip_node, "connected", ts, image=image,
                  dst_port=dst_port, user=user, command_line=cmdline)
        if image:
            p = _add_node(G, "process", f"{host}:{image}")
            _add_edge(G, p, ip_node, "connected", ts, dst_port=dst_port)
        return

    # --- Windows 4624: logon ----------------------------------------------
    if eid == "4624":
        target = dst_host or host
        if not target or not user:
            # fall back to generic handling below if we at least have endpoints
            pass
        else:
            u = _add_node(G, "user", user)
            h = _add_node(G, "host", target, **host_attrs)
            edge_attrs: Dict[str, Any] = {}
            if logon_type is not None:
                edge_attrs["logon_type"] = logon_type
            if share:
                edge_attrs["share"] = share
            if src_ip:
                edge_attrs["src_ip"] = src_ip
                _add_node(G, "ip", src_ip, external=_is_external_ip(src_ip))
            if src_user and src_user != user:
                su = _add_node(G, "user", src_user)
                _add_edge(G, su, h, "logon", ts, **edge_attrs)
            _add_edge(G, u, h, "logon", ts, **edge_attrs)
            # host->host lateral edge when the source workstation is known
            # (WorkstationName in 4624). This is what the lateral-movement
            # hunt keys on: Type 3 between workstations, admin shares.
            if src_host and src_host != target:
                sh = _add_node(G, "host", src_host)
                _add_edge(G, sh, h, "logon", ts, **edge_attrs)
            return

    # --- generic: any row naming a source and destination ------------------
    src_nid = None
    dst_nid = None
    if host:
        src_nid = _add_node(G, "host", host, **host_attrs)
    elif user:
        src_nid = _add_node(G, "user", user)
    elif src_ip:
        src_nid = _add_node(G, "ip", src_ip, external=_is_external_ip(src_ip))

    if dst_host:
        dst_nid = _add_node(G, "host", dst_host)
    elif dst_ip:
        dst_nid = _add_node(G, "ip", dst_ip, external=_is_external_ip(dst_ip))
    elif image and not src_nid:
        dst_nid = _add_node(G, "process", image)

    if src_nid and dst_nid and src_nid != dst_nid:
        etype = str(ev.get("action") or eid or "generic").lower() or "generic"
        extra: Dict[str, Any] = {}
        if logon_type is not None:
            extra["logon_type"] = logon_type
        if share:
            extra["share"] = share
        if image:
            extra["image"] = image
        if dst_port is not None:
            extra["dst_port"] = dst_port
        _add_edge(G, src_nid, dst_nid, etype, ts, **extra)
    elif image and host and src_nid:
        # process mentioned without a clear destination: attach to host
        p = _add_node(G, "process", f"{host}:{image}")
        _add_edge(G, src_nid, p, "spawned", ts, command_line=cmdline)
