"""Phase 1 input model: services, frontends, backends.

Everything here is *declared* — what the operator believes is true. None of it
is trusted by the scanner. Declarations are carried through to the output and
compared against what was observed, so a wrong declaration becomes a finding
rather than a silent contamination of the evidence.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field


class TlsMode(enum.Enum):
    TERMINATE = "terminate"
    REENCRYPT = "reencrypt"
    PASSTHROUGH = "passthrough"
    UNKNOWN = "unknown"


class FrontendType(enum.Enum):
    F5 = "f5"
    NGINX = "nginx"
    AZURE_FRONT_DOOR = "azure_front_door"
    AZURE_APP_GATEWAY = "azure_app_gateway"
    AZURE_APP_SERVICE = "azure_app_service"
    AWS_ALB = "aws_alb"
    AWS_NLB = "aws_nlb"
    AWS_CLOUDFRONT = "aws_cloudfront"
    CLOUDFLARE = "cloudflare"
    PALO_ALTO = "palo_alto"
    OTHER = "other"
    NONE = "none"        # no frontend; the endpoint is the origin
    UNKNOWN = "unknown"  # there is one, but we do not know what


class DataClassification(enum.Enum):
    """Who may see what this service handles. Declared, never inferred."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"
    UNKNOWN = "unknown"


class SensitivityHorizon(enum.Enum):
    """How long the data stays sensitive.

    This, not confidentiality level, is the question that matters for
    harvest-now-decrypt-later. Traffic captured today is decryptable once a
    cryptographically relevant quantum computer exists, so the exposure is a
    function of how long the contents remain worth reading. A session token is
    worthless in a week. A health record or a classified file is still
    sensitive in 2050, and classical-only key exchange on that endpoint today
    is a real liability rather than a theoretical one.
    """
    EPHEMERAL = "ephemeral"   # weeks
    SHORT = "short"           # 1-2 years
    MEDIUM = "medium"         # 5-10 years
    LONG = "long"             # decades
    UNKNOWN = "unknown"


# Declared frontend type does not gate any probe. It is recorded so that a
# type whose behaviour contradicts the observation can be flagged — an
# "aws_nlb" that presents its own certificate, for instance, is either
# mislabelled or is not the device actually answering.
_ALIASES = {
    "bigip": FrontendType.F5, "big-ip": FrontendType.F5,
    "ltm": FrontendType.F5, "avi": FrontendType.OTHER,
    "afd": FrontendType.AZURE_FRONT_DOOR,
    "frontdoor": FrontendType.AZURE_FRONT_DOOR,
    "front_door": FrontendType.AZURE_FRONT_DOOR,
    "appgw": FrontendType.AZURE_APP_GATEWAY,
    "app_gateway": FrontendType.AZURE_APP_GATEWAY,
    "application_gateway": FrontendType.AZURE_APP_GATEWAY,
    "appservice": FrontendType.AZURE_APP_SERVICE,
    "alb": FrontendType.AWS_ALB, "nlb": FrontendType.AWS_NLB,
    "elbv2": FrontendType.AWS_ALB,
    "cloudfront": FrontendType.AWS_CLOUDFRONT,
    "panorama": FrontendType.PALO_ALTO, "paloalto": FrontendType.PALO_ALTO,
    "": FrontendType.NONE, "null": FrontendType.NONE,
    "direct": FrontendType.NONE, "origin": FrontendType.NONE,
}


class InventoryError(ValueError):
    pass


def _coerce_frontend_type(value, *, absent=FrontendType.UNKNOWN) -> FrontendType:
    # A declared frontend block with no "type" means "there is a frontend and
    # we do not know what it is" — NOT "there is no frontend". Collapsing
    # those two inverts the topology logic, since NONE asserts the endpoint is
    # the origin.
    if value is None:
        return absent
    key = str(value).strip().lower().replace(" ", "_")
    if key in _ALIASES:
        return _ALIASES[key]
    try:
        return FrontendType(key)
    except ValueError:
        raise InventoryError(
            f"unknown frontend type {value!r}; use one of "
            f"{', '.join(t.value for t in FrontendType)}, or omit the field")


def _coerce_tls_mode(value) -> TlsMode:
    if value is None:
        return TlsMode.UNKNOWN
    key = str(value).strip().lower().replace("-", "").replace("_", "")
    mapping = {
        "terminate": TlsMode.TERMINATE, "termination": TlsMode.TERMINATE,
        "offload": TlsMode.TERMINATE, "ssloffload": TlsMode.TERMINATE,
        "reencrypt": TlsMode.REENCRYPT, "bridge": TlsMode.REENCRYPT,
        "sslbridging": TlsMode.REENCRYPT,
        "passthrough": TlsMode.PASSTHROUGH, "pass": TlsMode.PASSTHROUGH,
        "tcp": TlsMode.PASSTHROUGH,
        "unknown": TlsMode.UNKNOWN, "": TlsMode.UNKNOWN,
    }
    if key not in mapping:
        raise InventoryError(
            f"unknown tls_mode {value!r}; use terminate, reencrypt, "
            f"passthrough or unknown")
    return mapping[key]


_CLASSIFICATION_ALIASES = {
    "open": DataClassification.PUBLIC,
    "unclassified": DataClassification.PUBLIC,
    "staff": DataClassification.INTERNAL,
    "private": DataClassification.CONFIDENTIAL,
    "restricted": DataClassification.CONFIDENTIAL,
    "sensitive": DataClassification.CONFIDENTIAL,
    "pci": DataClassification.REGULATED,
    "phi": DataClassification.REGULATED,
    "phipa": DataClassification.REGULATED,
    "pii": DataClassification.REGULATED,
    "hipaa": DataClassification.REGULATED,
    "classified": DataClassification.REGULATED,
    "protected-b": DataClassification.REGULATED,
    "": DataClassification.UNKNOWN,
}

_HORIZON_ALIASES = {
    "session": SensitivityHorizon.EPHEMERAL,
    "transient": SensitivityHorizon.EPHEMERAL,
    "days": SensitivityHorizon.EPHEMERAL,
    "weeks": SensitivityHorizon.EPHEMERAL,
    "operational": SensitivityHorizon.SHORT,
    "years": SensitivityHorizon.MEDIUM,
    "decades": SensitivityHorizon.LONG,
    "permanent": SensitivityHorizon.LONG,
    "indefinite": SensitivityHorizon.LONG,
    "": SensitivityHorizon.UNKNOWN,
}


def _coerce_classification(value) -> DataClassification:
    if value is None:
        return DataClassification.UNKNOWN
    key = str(value).strip().lower().replace(" ", "-").replace("_", "-")
    if key in _CLASSIFICATION_ALIASES:
        return _CLASSIFICATION_ALIASES[key]
    try:
        return DataClassification(key)
    except ValueError:
        raise InventoryError(
            f"unknown data_classification {value!r}; use one of "
            f"{', '.join(c.value for c in DataClassification)}")


def _coerce_horizon(value) -> SensitivityHorizon:
    if value is None:
        return SensitivityHorizon.UNKNOWN
    key = str(value).strip().lower().replace(" ", "-").replace("_", "-")
    if key in _HORIZON_ALIASES:
        return _HORIZON_ALIASES[key]
    try:
        return SensitivityHorizon(key)
    except ValueError:
        raise InventoryError(
            f"unknown sensitivity_horizon {value!r}; use one of "
            f"{', '.join(h.value for h in SensitivityHorizon)}")


@dataclass
class Endpoint:
    """One address we can open a socket to."""
    host: str
    port: int = 443
    sni: str | None = None
    repeat: int = 1
    role: str = "backend"        # frontend | backend
    label: str | None = None

    @property
    def address(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


@dataclass
class Frontend:
    endpoint: Endpoint
    type: FrontendType = FrontendType.UNKNOWN
    declared_tls_mode: TlsMode = TlsMode.UNKNOWN
    notes: str | None = None


@dataclass
class Service:
    name: str
    sni: str | None = None
    frontend: Frontend | None = None
    backends: list[Endpoint] = field(default_factory=list)
    # Declared context. Never inferred, and unknown is a real answer rather
    # than a gap to be filled with a guess -- the same discipline the evidence
    # model applies to not_observed.
    data_classification: DataClassification = DataClassification.UNKNOWN
    sensitivity_horizon: SensitivityHorizon = SensitivityHorizon.UNKNOWN
    notes: str | None = None

    @property
    def context_declared(self) -> bool:
        return (self.data_classification is not DataClassification.UNKNOWN
                or self.sensitivity_horizon is not SensitivityHorizon.UNKNOWN)

    @property
    def has_frontend(self) -> bool:
        return (self.frontend is not None
                and self.frontend.type is not FrontendType.NONE)

    def all_endpoints(self) -> list[Endpoint]:
        endpoints = []
        if self.frontend:
            endpoints.append(self.frontend.endpoint)
        endpoints.extend(self.backends)
        return endpoints


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _parse_endpoint(raw, *, default_port: int, default_sni: str | None,
                    default_repeat: int, role: str) -> Endpoint:
    """Accepts a bare string ("30.1.1.2", "30.1.1.2:8443") or an object."""
    if isinstance(raw, str):
        host, port = _split_host_port(raw, default_port)
        return Endpoint(host=host, port=port, sni=default_sni,
                        repeat=default_repeat, role=role)
    if not isinstance(raw, dict):
        raise InventoryError(f"expected a string or object, got {type(raw).__name__}")

    host = raw.get("ip") or raw.get("host") or raw.get("address")
    if not host:
        raise InventoryError(f"endpoint is missing 'ip' or 'host': {raw!r}")
    port = int(raw.get("port", default_port))
    repeat = int(raw.get("repeat", default_repeat))
    if repeat < 1:
        raise InventoryError(f"repeat must be >= 1, got {repeat}")
    return Endpoint(host=str(host), port=port,
                    sni=raw.get("sni", default_sni), repeat=repeat,
                    role=role, label=raw.get("label"))


def _split_host_port(raw: str, default_port: int) -> tuple[str, int]:
    raw = raw.strip()
    if raw.startswith("["):
        close = raw.index("]")
        rest = raw[close + 1:]
        return raw[1:close], int(rest[1:]) if rest.startswith(":") else default_port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        return host, int(port)
    return raw, default_port


def parse_service(raw: dict, defaults: dict | None = None) -> Service:
    defaults = defaults or {}
    default_port = int(defaults.get("port", 443))
    default_repeat = int(defaults.get("repeat", 1))

    name = raw.get("service") or raw.get("name")
    if not name:
        raise InventoryError("service entry is missing 'service'")

    # The service name is the SNI unless told otherwise. This matters: probing
    # a backend IP with no SNI frequently returns a different (default)
    # virtual host than the one the frontend actually routes to, and the
    # resulting certificate mismatch would read as a topology signal when it
    # is really a probe artefact.
    sni = raw.get("sni", name)

    frontend = None
    raw_frontend = raw.get("frontend", raw.get("vip"))
    if raw_frontend is not None:
        ftype = _coerce_frontend_type(
            raw_frontend.get("type") if isinstance(raw_frontend, dict) else None,
            absent=FrontendType.UNKNOWN)
        endpoint = _parse_endpoint(
            raw_frontend, default_port=default_port, default_sni=sni,
            default_repeat=int(defaults.get("frontend_repeat", default_repeat)),
            role="frontend")
        mode = _coerce_tls_mode(
            raw_frontend.get("tls_mode") if isinstance(raw_frontend, dict) else None)
        frontend = Frontend(
            endpoint=endpoint, type=ftype, declared_tls_mode=mode,
            notes=raw_frontend.get("notes") if isinstance(raw_frontend, dict) else None)

    backends = [
        _parse_endpoint(entry, default_port=default_port, default_sni=sni,
                        default_repeat=default_repeat, role="backend")
        for entry in raw.get("backends", []) or []
    ]

    if frontend is None and not backends:
        raise InventoryError(
            f"service {name!r} declares neither a frontend nor any backends")

    return Service(
        name=name, sni=sni, frontend=frontend, backends=backends,
        data_classification=_coerce_classification(
            raw.get("data_classification",
                    defaults.get("data_classification"))),
        sensitivity_horizon=_coerce_horizon(
            raw.get("sensitivity_horizon",
                    defaults.get("sensitivity_horizon"))),
        notes=raw.get("notes"))


def load_inventory(raw: dict | list) -> list[Service]:
    """Accepts {"services": [...]}, a bare list, or a single service object."""
    if isinstance(raw, list):
        return [parse_service(entry) for entry in raw]
    if "services" in raw:
        defaults = raw.get("defaults", {})
        return [parse_service(entry, defaults) for entry in raw["services"]]
    return [parse_service(raw)]


def load_inventory_file(path: str) -> list[Service]:
    with open(path, "r", encoding="utf-8") as handle:
        return load_inventory(json.load(handle))
