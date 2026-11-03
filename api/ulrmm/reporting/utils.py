# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import binascii
import csv
import datetime
import functools
import io
import json
import re
import secrets
import shutil
import string
import time
import uuid
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Type, Union
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo

import regex
import yaml
from django.apps import apps
from django.conf import settings
from django.core.exceptions import (
    FieldDoesNotExist,
    FieldError,
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    SuspiciousFileOperation,
)
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.files.base import ContentFile
from django.db import OperationalError, connection, transaction
from django.db.models import Model, QuerySet
from django.db.models.manager import BaseManager
from django.utils import timezone as djangotime
from django.utils.crypto import get_random_string
from jinja2 import (
    FunctionLoader,
    Template,
    TemplateError,
    nodes,
    pass_context,
    pass_eval_context,
)
from jinja2.compiler import CodeGenerator
from jinja2.filters import do_center, do_format, do_indent, do_replace, sync_do_join
from jinja2.sandbox import SandboxedEnvironment, SecurityError, safe_range
from markupsafe import Markup, escape
from rest_framework.exceptions import ValidationError

from accounts.utils import has_superuser_rights
from ulrmm.logger import logger
from ulrmm.utils import RE_DB_VALUE, get_db_value

from . import conf
from .constants import (
    CUSTOM_FIELD_MODELS,
    FLAG_OPERATIONS,
    QUERY_OPERATIONS,
    REPORTING_MODELS,
    SCOPE_THROUGH,
    SUPERUSER_ONLY_MODELS,
    UNSCOPED_MODELS,
    UNSUPPORTED_OPERATIONS,
    can_read,
    get_property_fields,
)
from .custom_filters import as_tz, local_ips
from .markdown_ext import convert_markdown
from .permissions import can_view_reports
from .storage import report_assets_fs

if TYPE_CHECKING:
    from accounts.models import User

REPORT_FORMATS = ("html", "pdf", "plaintext")

ASSET_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
ASSET_URL_RE = re.compile(rf"asset://({ASSET_ID})")

# plotly express functions that draw from the given data only. Map, geo and
# image types are left out: they make the renderer fetch tiles and files.
CHART_TYPES = frozenset(
    (
        "area",
        "bar",
        "bar_polar",
        "box",
        "density_contour",
        "density_heatmap",
        "ecdf",
        "funnel",
        "funnel_area",
        "histogram",
        "icicle",
        "line",
        "line_3d",
        "line_polar",
        "line_ternary",
        "parallel_categories",
        "parallel_coordinates",
        "pie",
        "scatter",
        "scatter_3d",
        "scatter_matrix",
        "scatter_polar",
        "scatter_ternary",
        "strip",
        "sunburst",
        "timeline",
        "treemap",
        "violin",
    )
)
# chart settings that load something by URL
CHART_REFUSED_KEYS = frozenset(("images", "geo", "map", "mapbox"))

PLOTLY_STATIC_DIR = "reporting/js"

# a power or product whose result needs more bits than this is refused in templates
MAX_POWER_BITS = 100_000
# lists, tuples and mappings built in templates hold at most this many items
MAX_ITEMS = 1_000_000
# YAML variables may expand to at most this many nodes, aliases counted each time
MAX_YAML_NODES = 100_000


class ResolveModelException(Exception):
    pass


class InvalidDBOperationException(Exception):
    pass


class RenderLimitExceeded(TemplateError):
    pass


def _model(name: str) -> Type[Model]:
    return apps.get_model("reporting", name)


# ---------------------------------------------------------------------------
# render limits

_render_deadline: ContextVar[Optional[float]] = ContextVar(
    "report_render_deadline", default=None
)


def _check_deadline() -> None:
    deadline = _render_deadline.get()
    if deadline is not None and time.monotonic() > deadline:
        raise RenderLimitExceeded(
            f"Rendering took longer than {conf.render_timeout():g} seconds"
        )


@contextmanager
def render_deadline():
    """Start the render time limit unless an outer call already started it."""
    if _render_deadline.get() is not None:
        yield
        return
    token = _render_deadline.set(time.monotonic() + conf.render_timeout())
    try:
        yield
    finally:
        _render_deadline.reset(token)


@pass_context
def _loop_guard(context, iterable):
    # every for loop runs through this, so empty nested loops hit the deadline too
    for item in iterable:
        _check_deadline()
        yield item


def render_with_limits(template: Template, context: Dict[str, Any]) -> str:
    limit = conf.max_output_chars()
    with render_deadline():
        parts = []
        size = 0
        for chunk in template.generate(context):
            size += len(chunk)
            if size > limit:
                raise RenderLimitExceeded(
                    f"The report is larger than {limit // (1024 * 1024)} MB"
                )
            _check_deadline()
            parts.append(chunk)
        return "".join(parts)


def _check_size(size: int, limit: Optional[int] = None) -> None:
    if size > (conf.max_output_chars() if limit is None else limit):
        raise SecurityError("The result of this operation is too large")


def _checked(value: Any) -> Any:
    if isinstance(value, (str, bytes)):
        _check_size(len(value))
    elif isinstance(value, (list, tuple, dict, set, frozenset)):
        _check_size(len(value), MAX_ITEMS)
    return value


def _text_size(items: Any) -> int:
    # the text the items contribute; other objects count as one character
    return sum(len(item) if isinstance(item, str) else 1 for item in items)


_PRINTF_SPEC = re.compile(r"%%|%(?:\([^)]*\))?[#0+ -]*(\*|\d+)?(?:\.(\*|\d+))?")


def _check_width(number: str) -> None:
    if number == "*":
        raise SecurityError("Widths taken from arguments are not allowed")
    if number and (len(number) > 12 or int(number) > conf.max_output_chars()):
        raise SecurityError("This width or precision is too large")


def _check_printf(text: Any) -> None:
    if isinstance(text, str):
        for match in _PRINTF_SPEC.finditer(text):
            for number in match.groups():
                _check_width(number or "")


def _check_format_specs(text: str) -> None:
    for _, _, spec, _ in string.Formatter().parse(text):
        if not spec:
            continue
        if "{" in spec:
            raise SecurityError("Nested format fields are not allowed")
        for number in re.findall(r"\d+", spec):
            _check_width(number)


def _check_replace(text: str, old: str, new: str, count: Any = -1) -> None:
    times = text.count(old) if old else len(text) + 1
    if _is_int(count) and count >= 0:
        times = min(times, count)
    _check_size(len(text) + times * max(len(new) - len(old), 0))


def _check_str_call(text: str, name: str, args: Tuple[Any, ...]) -> None:
    """Refuse str methods that would build a huge string from small arguments."""
    if name in ("ljust", "rjust", "center", "zfill"):
        if args and _is_int(args[0]):
            _check_size(args[0])
    elif name == "expandtabs":
        tabsize = args[0] if args else 8
        if _is_int(tabsize):
            _check_size(len(text) + text.count("\t") * max(tabsize, 0))
    elif name == "replace" and len(args) >= 2:
        if isinstance(args[0], str) and isinstance(args[1], str):
            _check_replace(text, args[0], args[1], args[2] if len(args) > 2 else -1)
    elif name == "join" and args and isinstance(args[0], (list, tuple)):
        _check_size(_text_size(args[0]) + len(text) * len(args[0]))


def _center(value: Any, width: int = 80) -> str:
    if _is_int(width):
        _check_size(width)
    return do_center(value, width)


def _indent(value: Any, width: Union[int, str] = 4, *args: Any, **kwargs: Any) -> str:
    text = str(value)
    pad = len(width) if isinstance(width, str) else width
    if _is_int(pad):
        _check_size(len(text) + (text.count("\n") + 1) * max(pad, 0))
    return do_indent(value, width, *args, **kwargs)


def _format(value: Any, *args: Any, **kwargs: Any) -> str:
    _check_printf(str(value))
    return _checked(do_format(value, *args, **kwargs))


@pass_eval_context
def _replace(eval_ctx, value: Any, old: Any, new: Any, count: Optional[int] = None):
    _check_replace(str(value), str(old), str(new), -1 if count is None else count)
    return do_replace(eval_ctx, value, old, new, count)


@pass_eval_context
def _join(eval_ctx, value: Any, d: str = "", attribute: Any = None):
    items = list(value)
    if attribute is None:
        _check_size(_text_size(items) + len(str(d)) * len(items))
    return _checked(sync_do_join(eval_ctx, items, d, attribute))


def _checked_concat(parts: Any) -> str:
    # buffers of {% set %} blocks, macros and call blocks
    parts = list(parts)
    _check_size(_text_size(parts))
    return "".join(parts)


class ReportCodeGenerator(CodeGenerator):
    # the ~ operator has no binop hook, so its result is checked here
    def visit_Concat(self, node: nodes.Concat, frame: Any) -> None:
        self.write("environment.checked(")
        super().visit_Concat(node, frame)
        self.write(")")


# ---------------------------------------------------------------------------
# database values in HTML output

# Templates and variables are written by the report author and print as they
# are. Text read from the database is escaped when a template prints it.


class DatabaseText(str):
    """A text value read from the database."""

    def html(self) -> Markup:
        return escape(self)


class DatabaseJSON(DatabaseText):
    """JSON text of a data source, usable in HTML, attributes and <script>."""

    def html(self) -> Markup:
        return Markup(
            self.replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("'", "\\u0027")
        )


class DatabaseCSV(DatabaseText):
    """CSV text of a data source."""

    def html(self) -> Markup:
        return Markup(
            self.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )


class DatabaseRow(dict):
    """A data source row: its text values print as database text."""


def _from_database(obj: Any, value: Any) -> Any:
    if type(value) is str and isinstance(obj, (Model, DatabaseRow)):
        return DatabaseText(value)
    return value


def _finalize_html(value: Any) -> Any:
    return value.html() if isinstance(value, DatabaseText) else value


# ---------------------------------------------------------------------------
# regular expressions

MAX_PATTERN_LENGTH = 10_000


def _too_slow() -> RenderLimitExceeded:
    return RenderLimitExceeded("A regular expression ran past the time limit")


def _regex_timeout() -> float:
    _check_deadline()
    deadline = _render_deadline.get()
    if deadline is None:
        return conf.render_timeout()
    return max(deadline - time.monotonic(), 0.001)


def _bounded_matches(matches: Any) -> Any:
    try:
        yield from matches
    except TimeoutError:
        raise _too_slow()


# templates use the flag values of the stdlib module
_FLAGS = tuple(
    (getattr(re, name), getattr(regex, name))
    for name in ("ASCII", "IGNORECASE", "LOCALE", "MULTILINE", "DOTALL", "VERBOSE")
)


class BoundedPattern:
    """A compiled pattern whose searches stop at the render time limit."""

    def __init__(self, pattern: Any, flags: int = 0) -> None:
        own = 0
        for std, flag in _FLAGS:
            if flags & std:
                own |= flag
        self._compiled = regex.compile(pattern, own)
        if isinstance(pattern, str) and not flags & (re.ASCII | re.LOCALE):
            flags |= re.UNICODE
        self.pattern = pattern
        self.flags = int(flags)
        self.groups = self._compiled.groups
        self.groupindex = self._compiled.groupindex

    def _run(self, name: str, string: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(string, (str, bytes)):
            _check_size(len(string))
        kwargs["timeout"] = _regex_timeout()
        try:
            result = getattr(self._compiled, name)(string, *args, **kwargs)
        except TimeoutError:
            raise _too_slow()
        return _bounded_matches(result) if name == "finditer" else result

    def match(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("match", string, *args, **kwargs)

    def fullmatch(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("fullmatch", string, *args, **kwargs)

    def search(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("search", string, *args, **kwargs)

    def findall(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("findall", string, *args, **kwargs)

    def finditer(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("finditer", string, *args, **kwargs)

    def split(self, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._run("split", string, *args, **kwargs)

    def sub(self, repl: Any, string: Any, *args: Any, **kwargs: Any) -> Any:
        return _checked(self._subn(repl, string, *args, **kwargs)[0])

    def subn(self, repl: Any, string: Any, *args: Any, **kwargs: Any) -> Any:
        return self._subn(repl, string, *args, **kwargs)

    def _subn(self, repl: Any, string: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(string, (str, bytes)):
            _check_size(len(string))
        try:
            return self._compiled.subn(
                repl, string, *args, timeout=_regex_timeout(), **kwargs
            )
        except TimeoutError:
            raise _too_slow()

    def __repr__(self) -> str:
        flags = self.flags & ~re.UNICODE if isinstance(self.pattern, str) else 0
        if flags:
            return f"re.compile({self.pattern!r}, {re.RegexFlag(flags)!r})"
        return f"re.compile({self.pattern!r})"


def _compile(pattern: Any, flags: int = 0) -> BoundedPattern:
    if isinstance(pattern, BoundedPattern):
        return pattern
    if isinstance(pattern, (str, bytes)) and len(pattern) > MAX_PATTERN_LENGTH:
        raise SecurityError("This regular expression is too long")
    return BoundedPattern(pattern, flags)


def _re_match(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _compile(pattern, flags).match(string)


def _re_fullmatch(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _compile(pattern, flags).fullmatch(string)


def _re_search(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _compile(pattern, flags).search(string)


def _re_findall(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _compile(pattern, flags).findall(string)


def _re_finditer(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _compile(pattern, flags).finditer(string)


def _re_split(pattern: Any, string: Any, maxsplit: int = 0, flags: int = 0) -> Any:
    return _compile(pattern, flags).split(string, maxsplit)


def _re_sub(pattern: Any, repl: Any, string: Any, count: int = 0, flags: int = 0):
    return _compile(pattern, flags).sub(repl, string, count)


def _re_subn(pattern: Any, repl: Any, string: Any, count: int = 0, flags: int = 0):
    return _compile(pattern, flags).subn(repl, string, count)


def _re_namespace() -> SimpleNamespace:
    """The re module for templates, run by a matcher with a time limit."""
    names = {name: getattr(re, name) for name in re.__all__}
    # never the stdlib functions: they have no time limit
    names = {name: value for name, value in names.items() if not callable(value)}
    names.update(
        RegexFlag=re.RegexFlag,
        Pattern=re.Pattern,
        Match=re.Match,
        error=regex.error,
        compile=_compile,
        escape=re.escape,
        purge=regex.purge,
        match=_re_match,
        fullmatch=_re_fullmatch,
        search=_re_search,
        findall=_re_findall,
        finditer=_re_finditer,
        split=_re_split,
        sub=_re_sub,
        subn=_re_subn,
    )
    return SimpleNamespace(**names)


# ---------------------------------------------------------------------------
# Jinja environment


def _template_source(name: str) -> Optional[str]:
    html = (
        _model("ReportHTMLTemplate")
        .objects.filter(name=name)
        .values_list("html", flat=True)
        .first()
    )
    if html is not None:
        return html
    return (
        _model("ReportTemplate")
        .objects.filter(name=name)
        .values_list("template_md", flat=True)
        .first()
    )


def db_template_loader(name: str) -> Optional[Tuple[str, None, Any]]:
    source = _template_source(name)
    if source is None:
        return None
    # cached templates are reused only while the stored source is unchanged
    return source, None, lambda: _template_source(name) == source


def _readable_instance(instance: Model, name: str) -> bool:
    return can_read(instance._meta.label, name)


def _public_names(module: Any, names: Tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        **{name: getattr(module, name) for name in names if hasattr(module, name)}
    )


class ReportSandboxedEnvironment(SandboxedEnvironment):
    """Sandbox for report templates.

    On top of the standard sandbox it refuses every callable attribute of a
    model instance, queryset or manager, and any attribute can_read refuses.
    Templates can read data but never run model code. Operations that could
    build huge values from small input are checked before they run.
    """

    intercepted_binops = frozenset(("*", "**", "+", "%"))
    code_generator_class = ReportCodeGenerator
    concat = staticmethod(_checked_concat)
    checked = staticmethod(_checked)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            loader=FunctionLoader(db_template_loader),
            comment_start_string="{=",
            comment_end_string="=}",
            extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
            **kwargs,
        )
        self.globals["range"] = safe_range
        self.globals["datetime"] = _public_names(
            datetime,
            (
                "date",
                "datetime",
                "time",
                "timedelta",
                "timezone",
                "tzinfo",
                "MINYEAR",
                "MAXYEAR",
                "UTC",
            ),
        )
        self.globals["ZoneInfo"] = ZoneInfo
        self.globals["re"] = _re_namespace()
        self.filters["as_tz"] = as_tz
        self.filters["local_ips"] = local_ips
        self.filters["loop_guard"] = _loop_guard
        self.filters["center"] = _center
        self.filters["indent"] = _indent
        self.filters["format"] = _format
        self.filters["replace"] = _replace
        self.filters["join"] = _join

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        if not super().is_safe_attribute(obj, attr, value):
            return False
        if isinstance(obj, Model):
            if not can_read(obj._meta.label, attr):
                return False
            return not callable(value)
        if isinstance(obj, (QuerySet, BaseManager)):
            return not callable(value)
        # the pattern behind a match has no time limit
        if isinstance(obj, regex.Match) and attr == "re":
            return False
        return True

    def getattr(self, obj: Any, attribute: str) -> Any:
        return _from_database(obj, super().getattr(obj, attribute))

    def getitem(self, obj: Any, argument: Any) -> Any:
        return _from_database(obj, super().getitem(obj, argument))

    def call(__self, __context, __obj, *args, **kwargs):
        _check_deadline()
        owner = getattr(__obj, "__self__", None)
        if isinstance(owner, str):
            _check_str_call(owner, getattr(__obj, "__name__", ""), args)
        result = super().call(__context, __obj, *args, **kwargs)
        # list.extend and dict.update grow the object they belong to
        if isinstance(owner, (list, dict, set)):
            _checked(owner)
        return _checked(result)

    def wrap_str_format(self, value: Any) -> Any:
        wrapper = super().wrap_str_format(value)
        if wrapper is None:
            return None
        _check_format_specs(value.__self__)

        @functools.wraps(wrapper)
        def checked_format(*args: Any, **kwargs: Any) -> str:
            return _checked(wrapper(*args, **kwargs))

        return checked_format

    def call_binop(self, context, operator: str, left: Any, right: Any) -> Any:
        if operator == "**" and _is_int(left) and _is_int(right):
            if (
                right > 0
                and abs(left) > 1
                and right * abs(left).bit_length() > MAX_POWER_BITS
            ):
                raise SecurityError("The result of this power is too large")
        elif operator == "*" and _is_int(left) and _is_int(right):
            if left.bit_length() + right.bit_length() > MAX_POWER_BITS:
                raise SecurityError("The result of this product is too large")
        elif operator == "*":
            for sequence, times in ((left, right), (right, left)):
                if isinstance(sequence, str) and _is_int(times):
                    _check_size(len(sequence) * times)
                elif isinstance(sequence, (list, tuple)) and _is_int(times):
                    _check_size(len(sequence) * times, MAX_ITEMS)
                    _check_size(_text_size(sequence) * times)
        elif operator == "+":
            if isinstance(left, str) and isinstance(right, str):
                _check_size(len(left) + len(right))
            elif isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
                _check_size(len(left) + len(right), MAX_ITEMS)
        elif operator == "%":
            _check_printf(left)
        return super().call_binop(context, operator, left, right)

    def _parse(self, source, name, filename):
        tree = super()._parse(source, name, filename)
        for loop in tree.find_all(nodes.For):
            loop.iter = nodes.Filter(
                loop.iter, "loop_guard", [], [], None, None, lineno=loop.lineno
            )
        return tree


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# html and markdown output escapes database text, plain text does not
env = ReportSandboxedEnvironment(finalize=_finalize_html)
plaintext_env = ReportSandboxedEnvironment()


def environment_for(template_type: str) -> ReportSandboxedEnvironment:
    return plaintext_env if template_type == "plaintext" else env


# ---------------------------------------------------------------------------
# variables YAML

# anything that does not match exactly is plain "now", as it always was
_NOW_OFFSET = re.compile(r"^(weeks|days|hours|minutes|seconds|microseconds)=(-?\d*)$")


class ReportYAMLLoader(yaml.SafeLoader):
    pass


def _construct_now(loader: ReportYAMLLoader, node: yaml.Node):
    value = loader.construct_scalar(node)
    now = djangotime.now()
    match = _NOW_OFFSET.match(str(value))
    if not match:
        return now
    unit, amount = match.groups()
    if amount in ("", "-"):
        raise yaml.constructor.ConstructorError(
            None,
            None,
            f"!now {value}: the offset must be a whole number, for example days=-30",
            node.start_mark,
        )
    return now + datetime.timedelta(**{unit: int(amount)})


ReportYAMLLoader.add_constructor("!now", _construct_now)

_PLAIN_PLACEHOLDER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_STR_TAG = "tag:yaml.org,2002:str"


def _fill_placeholders(
    loader: ReportYAMLLoader, root: yaml.Node, marker: re.Pattern, values: List[str]
) -> None:
    seen = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.ScalarNode):
            if not marker.search(node.value):
                continue
            filled = marker.sub(lambda m: values[int(m.group(1))], node.value)
            if node.style is None and node.tag == _STR_TAG:
                # an unquoted value gets the type its text implies, as if it
                # had been typed in, but never becomes a mapping or a list
                node.tag = loader.resolve(yaml.ScalarNode, filled, (True, False))
            node.value = filled
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                stack.extend((key, value))


def _check_yaml_size(root: yaml.Node) -> None:
    """Refuse aliases that expand to a huge or a recursive document."""
    sizes: Dict[int, int] = {}
    open_nodes = set()
    stack: List[Tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, finished = stack.pop()
        if isinstance(node, yaml.SequenceNode):
            children = list(node.value)
        elif isinstance(node, yaml.MappingNode):
            children = [child for pair in node.value for child in pair]
        else:
            children = []
        if finished:
            open_nodes.discard(id(node))
            sizes[id(node)] = 1 + sum(sizes[id(child)] for child in children)
            if sizes[id(node)] > MAX_YAML_NODES:
                raise ValueError(
                    f"Template variables expand to more than {MAX_YAML_NODES} values"
                )
            continue
        if id(node) in sizes:
            continue
        if id(node) in open_nodes:
            raise ValueError("Template variables may not contain recursive aliases")
        open_nodes.add(id(node))
        stack.append((node, True))
        stack.extend((child, False) for child in children if id(child) not in sizes)


def _can_read_key_store(user: Optional["User"]) -> bool:
    if user is None or has_superuser_rights(user):
        return True
    role = getattr(user, "role", None)
    return bool(role and role.can_view_global_keystore)


def parse_variables(
    text: str,
    dependencies: Optional[Dict[str, Any]] = None,
    user: Optional["User"] = None,
) -> dict:
    """Parse the variables YAML with placeholders filled in.

    Placeholders are swapped for markers before parsing and the values are put
    into the parsed scalars, so a value can never add keys or break the YAML.
    Key store values need a user who may view the key store; otherwise the
    placeholder stays as it is, like one that points at a credential.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise ValueError("Template variables must be YAML text")
    dependencies = dependencies or {}

    token = secrets.token_hex(6)
    marker = re.compile(rf"x{token}v(\d+)x")
    values: List[str] = []

    def stash(value: Any) -> str:
        values.append(str(value))
        return f"x{token}v{len(values) - 1}x"

    resolved: Dict[str, str] = {}
    for match in RE_DB_VALUE.finditer(text):
        placeholder = match.group(1)
        if placeholder in resolved:
            continue
        path = placeholder[2:-2].strip()
        first = path.split(".", 1)[0]
        instance = dependencies.get(first)
        if first == "global":
            if not _can_read_key_store(user):
                continue
            instance = None
        elif not isinstance(instance, Model):
            continue
        value = get_db_value(
            string=path, instance=instance, readable=_readable_instance
        )
        if value:
            resolved[placeholder] = stash(value)
    for placeholder, replacement in resolved.items():
        text = text.replace(placeholder, replacement)

    def plain(match: re.Match) -> str:
        value = dependencies.get(match.group(1))
        return stash(value) if value else match.group(0)

    text = _PLAIN_PLACEHOLDER.sub(plain, text)

    loader = ReportYAMLLoader(text)
    try:
        root = loader.get_single_node()
        if root is None:
            return {}
        _check_yaml_size(root)
        if values:
            _fill_placeholders(loader, root, marker, values)
        data = loader.construct_document(root)
    finally:
        loader.dispose()

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Template variables must be a YAML mapping")
    return data


# ---------------------------------------------------------------------------
# dependencies

DEPENDENCY_MODELS = {
    "client": ("clients.Client", "pk"),
    "site": ("clients.Site", "pk"),
    "agent": ("agents.Agent", "agent_id"),
}
RESERVED_DEPENDENCIES = ("data_sources", "charts")


def resolve_dependencies(
    dependencies: Optional[Dict[str, Any]], user: Optional["User"] = None
) -> Dict[str, Any]:
    if dependencies is None:
        dependencies = {}
    if not isinstance(dependencies, dict):
        raise ValueError("Dependencies must be an object")

    resolved = dict(dependencies)
    for key in RESERVED_DEPENDENCIES:
        if key in resolved:
            raise ValueError(f"{key} cannot be used as a dependency name")

    for key, (label, lookup) in DEPENDENCY_MODELS.items():
        if key in resolved:
            model = apps.get_model(label)
            # objects outside the user's role are reported as not found
            resolved[key] = scoped_queryset(model, user).get(**{lookup: resolved[key]})
    return resolved


def check_dependencies(dependencies: Any, user: Optional["User"]) -> None:
    """Refuse dependencies that do not exist or are outside the user's role."""
    try:
        resolve_dependencies(dependencies, user)
    except (
        ObjectDoesNotExist,
        MultipleObjectsReturned,
        InvalidDBOperationException,
        ValueError,
        TypeError,
    ) as error:
        raise ValidationError({"dependencies": [report_error_message(error)]})


def process_dependencies(
    variables: str,
    dependencies: Optional[Dict[str, Any]],
    user: Optional["User"] = None,
) -> Dict[str, Any]:
    resolved = resolve_dependencies(dependencies, user)
    return {**parse_variables(variables, resolved, user), **resolved}


# ---------------------------------------------------------------------------
# data queries


def resolve_model(data_source: Any) -> Dict[str, Any]:
    if not isinstance(data_source, dict) or "model" not in data_source:
        raise ResolveModelException("Model key must be present on data_source")

    name = data_source["model"]
    for model_name, app_label in REPORTING_MODELS:
        if isinstance(name, str) and name.lower() == model_name.lower():
            try:
                model = apps.get_model(app_label, model_name)
            except LookupError:
                raise ResolveModelException(
                    f"Model: {model_name} does not exist in app: {app_label}"
                )
            return {**data_source, "model": model}

    raise ResolveModelException(f"Model lookup failed for {name}")


def _lookup_field(model: Type[Model], name: str):
    if name == "pk":
        return model._meta.pk
    try:
        return model._meta.get_field(name)
    except FieldDoesNotExist:
        pass
    for relation in model._meta.related_objects:
        if relation.get_accessor_name() == name:
            return relation
    return None


def check_lookup_path(
    model: Type[Model], path: str, user: Optional["User"] = None
) -> None:
    """Refuse a lookup path that reads what the report may not see.

    Every field on the path must pass can_read on the model that owns it. A
    relation to a model that cannot be read may still be selected as its key
    or tested with a lookup such as isnull.

    A restricted user may only follow forward foreign keys and one-to-one
    fields. They lead from a row in the user's scope to rows of the same
    client, while reverse and many-to-many relations, for example from a
    shared policy back to its agents, reach rows of other clients.
    """
    if not isinstance(path, str):
        return
    unrestricted = user is None or has_superuser_rights(user)
    # a role without client or site limits sees every row, so no relation can
    # leave its scope
    any_relation = unrestricted or _sees_all_rows(user)
    lookup = path[1:] if path.startswith("-") else path
    current = model
    for part in lookup.split("__"):
        field = _lookup_field(current, part)
        if field is None:
            return
        name = current._meta.pk.name if part == "pk" else field.name
        if not can_read(current._meta.label, name, unrestricted):
            raise InvalidDBOperationException(f"Lookup {path} is not allowed")
        if not field.is_relation or field.related_model is None:
            return
        if not any_relation and (field.many_to_many or not field.concrete):
            raise InvalidDBOperationException(
                f"Lookup {path} is not allowed: it follows a relation that leaves "
                "your permitted clients"
            )
        current = field.related_model


def _check_operation_paths(
    model: Type[Model], value: Any, user: Optional["User"] = None
) -> None:
    if isinstance(value, str):
        check_lookup_path(model, value, user)
    elif isinstance(value, (list, tuple)):
        for item in value:
            check_lookup_path(model, item, user)
    elif isinstance(value, dict):
        for key in value:
            check_lookup_path(model, key, user)


def _names(key: str, value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
        return list(value)
    raise InvalidDBOperationException(f"{key} must be a name or a list of names")


def _has_agent_relation(model: Type[Model]) -> bool:
    try:
        field = model._meta.get_field("agent")
    except FieldDoesNotExist:
        return False
    return bool(field.is_relation and field.related_model._meta.label == "agents.Agent")


# filter_by_role scopes these by their own client and site; any other model
# needs an agent relation, or filter_by_role returns it unfiltered
ROLE_FILTERED_MODELS = frozenset(
    ("agents.Agent", "clients.Client", "clients.Site", "alerts.Alert")
)


def _sees_all_rows(user: "User") -> bool:
    """A role without client and site limits, which filter_by_role leaves
    unfiltered (rows without an agent included)."""
    role = user.role
    return bool(role) and not (
        role.can_view_clients.exists() or role.can_view_sites.exists()
    )


def scoped_queryset(model: Type[Model], user: Optional["User"] = None) -> QuerySet:
    """All rows of model that user may see. Fails closed."""
    queryset = model.objects.all()
    if user is None:
        return queryset

    label = model._meta.label
    if label in SUPERUSER_ONLY_MODELS and not has_superuser_rights(user):
        raise InvalidDBOperationException(
            f"{model.__name__} can only be queried by superusers"
        )
    if has_superuser_rights(user) or _sees_all_rows(user):
        return queryset

    try:
        if label in SCOPE_THROUGH:
            lookup, parent, parent_field = SCOPE_THROUGH[label]
            visible = apps.get_model(parent).objects.filter_by_role(user)
            return queryset.filter(**{f"{lookup}__in": visible.values(parent_field)})
        if hasattr(queryset, "filter_by_role") and (
            label in ROLE_FILTERED_MODELS or _has_agent_relation(model)
        ):
            return queryset.filter_by_role(user)
        if _has_agent_relation(model):
            visible = apps.get_model("agents.Agent").objects.filter_by_role(user)
            return queryset.filter(agent__in=visible)
        if label in UNSCOPED_MODELS:
            return queryset
        raise InvalidDBOperationException(f"{label} has no role filter")
    except Exception as error:
        logger.error(f"reporting: role filter for {label} failed: {error}")
        raise InvalidDBOperationException(
            f"Permissions for {model.__name__} could not be applied"
        )


def _effective_limit(data_source: Dict[str, Any], default: Optional[int]) -> int:
    limits = [conf.max_rows()]
    if default:
        limits.append(default)
    limit = data_source.get("limit")
    # 0, null and false mean no limit, true counts as 1
    if limit is True:
        limit = 1
    if limit:
        if not _is_int(limit) or limit < 0:
            raise InvalidDBOperationException(
                "limit must be a whole number of 0 or more"
            )
        limits.append(limit)
    return min(limits)


def add_custom_fields(
    data: Union[List[Dict[str, Any]], Dict[str, Any]],
    fields_to_add: List[str],
    model_name: str,
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """Add a custom_fields mapping to each row, keyed by field name."""
    from core.models import CustomField

    model_name = model_name.lower()
    if model_name not in CUSTOM_FIELD_MODELS or not fields_to_add or not data:
        return data

    rows = data if isinstance(data, list) else [data]
    fields = list(CustomField.objects.filter(model=model_name, name__in=fields_to_add))
    if not fields:
        return data

    value_model = {
        "agent": apps.get_model("agents.AgentCustomField"),
        "client": apps.get_model("clients.ClientCustomField"),
        "site": apps.get_model("clients.SiteCustomField"),
    }[model_name]
    records = {
        (getattr(record, f"{model_name}_id"), record.field_id): record
        for record in value_model.objects.filter(
            field__in=fields, **{f"{model_name}_id__in": [row["id"] for row in rows]}
        ).select_related("field")
    }
    for row in rows:
        row["custom_fields"] = DatabaseRow(
            (
                field.name,
                (
                    records[(row["id"], field.id)].value
                    if (row["id"], field.id) in records
                    else field.default_value
                ),
            )
            for field in fields
        )
    return data


def add_property_fields(
    rows: List[Dict[str, Any]], model: Type[Model], names: List[str]
) -> None:
    allowed = get_property_fields(model)
    wanted = [name for name in dict.fromkeys(names) if name in allowed]
    if not wanted or not rows:
        return
    instances = model.objects.in_bulk([row["id"] for row in rows])
    for row in rows:
        instance = instances.get(row["id"])
        for name in wanted:
            value = getattr(instance, name) if instance is not None else None
            unreadable = isinstance(value, Model) and not can_read(
                value._meta.label, None
            )
            row[name] = None if unreadable else value


def _to_csv(result: Any, rename: Optional[Dict[str, str]]) -> str:
    if result is None:
        rows = []
    elif isinstance(result, list):
        rows = result
    else:
        rows = [result]

    columns: List[str] = []
    for row in rows:
        for key in row:
            if key != "id" and key not in columns:
                columns.append(key)

    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([str((rename or {}).get(c, c)) for c in columns])
    for row in rows:
        writer.writerow(["" if row.get(c) is None else row.get(c) for c in columns])
    return out.getvalue()


def build_queryset(
    data_source: Dict[str, Any],
    limit: Optional[int] = None,
    user: Optional["User"] = None,
) -> Any:
    """Run one data query.

    Returns an int for count, a dict (or None) for get and first, a list of
    dicts otherwise, and a string when json or csv is set.
    """
    model = data_source.get("model")
    if not (
        isinstance(model, type)
        and issubclass(model, Model)
        and (model.__name__, model._meta.app_label) in REPORTING_MODELS
    ):
        raise ResolveModelException(f"Model lookup failed for {model}")

    operations = [(key, value) for key, value in data_source.items() if key != "model"]
    for key, value in operations:
        if key in UNSUPPORTED_OPERATIONS:
            raise InvalidDBOperationException(f"{key} is not supported in data queries")
        if key not in QUERY_OPERATIONS:
            raise InvalidDBOperationException(
                f"DB operation: {key} not allowed. Supported operations: "
                f"{', '.join(QUERY_OPERATIONS)}"
            )
        _check_operation_paths(model, value, user)

    flags = {
        key
        for key in FLAG_OPERATIONS
        if key in data_source and data_source[key] is not False
    }

    queryset = scoped_queryset(model, user)
    for key, value in operations:
        if key in ("filter", "exclude"):
            if not isinstance(value, dict):
                raise InvalidDBOperationException(
                    f"{key} must be a mapping of lookups to values"
                )
            queryset = getattr(queryset, key)(**value)
        elif key in ("order_by", "select_related"):
            queryset = getattr(queryset, key)(*_names(key, value))
        elif key == "get" and "get" in flags and isinstance(value, dict):
            queryset = queryset.filter(**value)
        elif key == "prefetch_related":
            # rows come out as dicts, so prefetching would only fail
            _names(key, value)

    if "count" in flags:
        return queryset.count()

    defer = _names("defer", data_source["defer"]) if "defer" in data_source else []
    if "only" in data_source or "values" in data_source:
        key = "only" if "only" in data_source else "values"
        fields = [name for name in _names(key, data_source[key]) if name not in defer]
        if "id" not in fields:
            fields.append("id")
    elif defer:
        fields = [
            field.name
            for field in model._meta.concrete_fields
            if field.name not in defer or field.primary_key
        ]
    else:
        fields = []
    rows = queryset.values(*fields)

    custom_fields = data_source.get("custom_fields")
    properties = data_source.get("properties")
    if custom_fields is not None:
        custom_fields = _names("custom_fields", custom_fields)
    if properties is not None:
        properties = _names("properties", properties)

    if "get" in flags or "first" in flags:
        result = rows.get() if "get" in flags else rows.first()
        if result is not None:
            result = DatabaseRow(result)
        batch = [result] if result is not None else []
    else:
        result = [
            DatabaseRow(row) for row in rows[: _effective_limit(data_source, limit)]
        ]
        batch = result

    if custom_fields:
        add_custom_fields(batch, custom_fields, model.__name__)
    if properties:
        add_property_fields(batch, model, properties)

    if "json" in flags:
        return DatabaseJSON(json.dumps(result, default=str))
    if "csv" in flags:
        rename = data_source["csv"] if isinstance(data_source["csv"], dict) else None
        return DatabaseCSV(_to_csv(result, rename))
    return result


@contextmanager
def _statement_timeout():
    """Limit the queries of one data source to the time left for the render."""
    deadline = _render_deadline.get()
    if deadline is None or connection.vendor != "postgresql":
        yield
        return
    milliseconds = max(1, int((deadline - time.monotonic()) * 1000))
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('statement_timeout')")
        previous = cursor.fetchone()[0]
        try:
            with transaction.atomic():
                cursor.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    [str(milliseconds)],
                )
                yield
        except OperationalError as error:
            cause = error.__cause__
            if "57014" in (
                getattr(cause, "sqlstate", None),
                getattr(cause, "pgcode", None),
            ):
                raise RenderLimitExceeded(
                    f"A data query took longer than {conf.render_timeout():g} seconds"
                )
            raise
        finally:
            cursor.execute(
                "SELECT set_config('statement_timeout', %s, true)", [previous]
            )


def process_data_sources(
    variables: dict[str, Any],
    limit_query_results: Optional[int] = None,
    user: Optional["User"] = None,
) -> dict[str, Any]:
    data_sources = variables.get("data_sources")
    if not isinstance(data_sources, dict):
        return variables

    for name, query in data_sources.items():
        if isinstance(query, dict):
            _check_deadline()
            with _statement_timeout():
                data_sources[name] = build_queryset(
                    data_source=resolve_model(data_source=query),
                    limit=limit_query_results,
                    user=user,
                )
    return variables


# ---------------------------------------------------------------------------
# charts


def plotly_js_url() -> str:
    import plotly

    static_url = settings.STATIC_URL
    if not static_url.startswith(("http://", "https://")):
        static_url = f"{conf.base_url()}{static_url}"
    return f"{static_url.rstrip('/')}/{PLOTLY_STATIC_DIR}/plotly-{plotly.__version__}.min.js"


def copy_plotly_js() -> Path:
    """Put the bundled plotly.js into the static source folder.

    collectstatic publishes it, so HTML charts load the script from this
    server and not from a public CDN.
    """
    import plotly

    source = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
    target_dir = Path(settings.STATICFILES_DIRS[0]) / PLOTLY_STATIC_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"plotly-{plotly.__version__}.min.js"
    for old in target_dir.glob("plotly-*.min.js"):
        if old != target:
            old.unlink()
    shutil.copyfile(source, target)
    return target


def _check_chart_settings(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key in CHART_REFUSED_KEYS:
                    raise ValueError(f"Chart setting {key} is not allowed")
                stack.append(child)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, str) and ("://" in item or item.startswith("//")):
            raise ValueError("Chart settings may not contain URLs")


def _figure_svg(figure) -> str:
    import kaleido

    # mathjax off and plotly.js from the installed package: no network access
    svg = kaleido.calc_fig_sync(
        figure.to_dict(),
        opts={"format": "svg", "width": 700, "height": 500},
        kopts={"mathjax": False},
    )
    return svg.decode() if isinstance(svg, bytes) else svg


def generate_chart(
    type: str,
    format: str,
    options: Dict[str, Any],
    traces: Optional[Dict[str, Any]] = None,
    layout: Optional[Dict[str, Any]] = None,
) -> Optional[Markup]:
    if type not in CHART_TYPES:
        raise ValueError(f"Invalid chart type: {type}")
    _check_chart_settings(
        [{k: v for k, v in options.items() if k != "data_frame"}, traces, layout]
    )

    import plotly.express as px

    figure = getattr(px, type)(**options)
    if traces:
        figure.update_traces(traces)
    if layout:
        figure.update_layout(layout)

    if format == "html":
        return Markup(figure.to_html(full_html=False, include_plotlyjs=plotly_js_url()))
    if format == "image":
        return Markup(_figure_svg(figure))
    return None


def _walk_path(variables: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    value: Any = variables
    for part in path.split("."):
        if not isinstance(value, dict) or value.get(part) is None:
            return False, None
        value = value[part]
    return True, value


def process_chart_variables(variables: Dict[str, Any]) -> Dict[str, Any]:
    charts = variables.get("charts")
    if not isinstance(charts, dict):
        return variables

    for name in list(charts):
        _check_deadline()
        chart = charts[name]
        if not isinstance(chart, dict) or not isinstance(chart.get("options"), dict):
            continue
        options = chart["options"]

        data_frame = options.get("data_frame")
        if isinstance(data_frame, str):
            found, value = _walk_path(variables, data_frame)
            if not found:
                continue
            if not value:
                del charts[name]
                continue
            options = {**options, "data_frame": value}

        if "chartType" not in chart or "outputType" not in chart:
            raise ValueError(f"Chart {name} needs chartType and outputType")

        charts[name] = generate_chart(
            type=chart["chartType"],
            format=chart["outputType"],
            options=options,
            traces=chart.get("traces"),
            layout=chart.get("layout"),
        )
    return variables


# ---------------------------------------------------------------------------
# rendering


def prep_variables_for_template(
    variables: str,
    dependencies: dict[str, Any] | None = None,
    limit_query_results: Optional[int] = None,
    user: Optional["User"] = None,
) -> dict[str, Any]:
    with render_deadline():
        variables = process_dependencies(
            variables=variables, dependencies=dependencies, user=user
        )
        variables = process_data_sources(
            variables=variables, limit_query_results=limit_query_results, user=user
        )
        return process_chart_variables(variables=variables)


def generate_html(
    template: str,
    template_type: str,
    css: str = "",
    html_template: int | None = None,
    variables: str = "",
    dependencies: dict[str, Any] | None = None,
    user: Optional["User"] = None,
) -> tuple[str, dict[str, Any]]:
    environment = environment_for(template_type)
    # syntax errors are reported against the source the user wrote
    environment.parse(template)

    source = convert_markdown(template) if template_type == "markdown" else template
    if html_template:
        base = (
            _model("ReportHTMLTemplate")
            .objects.filter(pk=html_template)
            .values_list("name", flat=True)
            .first()
        )
        if base is not None:
            source = "{% extends " + json.dumps(base) + " %}\n" + source

    compiled = environment.from_string(source)
    # one time limit for the variables, the data queries and the rendering
    with render_deadline():
        variables = prep_variables_for_template(
            variables=variables, dependencies=dependencies, user=user
        )
        # the template's own css wins over a variable of that name
        context = {**variables, "css": Markup(css or "")}
        return render_with_limits(compiled, context), variables


# ---------------------------------------------------------------------------
# PDF


def report_asset_url(url: str) -> str:
    """The URL to load for a report: data URIs and files in the asset folder only."""
    if url.lower().startswith("data:"):
        return url

    parts = urlsplit(url)
    if parts.scheme.lower() == "file" and parts.netloc in ("", "localhost"):
        root = Path(conf.assets_base_path()).resolve()
        target = Path(unquote(parts.path)).resolve()
        if target.is_relative_to(root) and target != root and target.is_file():
            return target.as_uri()

    raise ValueError("Only report assets can be loaded into a report")


def report_url_fetcher():
    """URL fetcher for WeasyPrint that loads only what report_asset_url allows."""
    from weasyprint.urls import URLFetcher

    class ReportURLFetcher(URLFetcher):
        def fetch(self, url, headers=None):
            return super().fetch(report_asset_url(url), headers)

    return ReportURLFetcher(allowed_protocols=("data", "file"), allow_redirects=False)


def generate_pdf(html: str, css: str = "") -> bytes:
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    font_config = FontConfiguration()
    fetcher = report_url_fetcher()
    stylesheets = None
    if css:
        stylesheets = [CSS(string=css, font_config=font_config, url_fetcher=fetcher)]
    document = HTML(string=html, url_fetcher=fetcher)
    return document.write_pdf(stylesheets=stylesheets, font_config=font_config)


# ---------------------------------------------------------------------------
# assets


def _referenced_assets(text: str) -> Dict[str, Any]:
    ids = list(dict.fromkeys(ASSET_URL_RE.findall(text or "")))
    if not ids:
        return {}
    found = {
        str(asset.id): asset
        for asset in _model("ReportAsset").objects.filter(id__in=ids)
    }
    return {asset_id: found[asset_id] for asset_id in ids if asset_id in found}


def normalize_asset_url(text: str, format: str) -> str:
    assets = _referenced_assets(text)
    if not assets:
        return text

    def replace(match: re.Match) -> str:
        asset = assets.get(match.group(1))
        if asset is None:
            return match.group(0)
        try:
            if format == "html":
                return f"{report_assets_fs.url(asset.file.name)}?id={asset.id}"
            return Path(report_assets_fs.path(asset.file.name)).as_uri()
        except SuspiciousFileOperation:
            return match.group(0)

    return ASSET_URL_RE.sub(replace, text)


def restore_asset_links(text: str) -> str:
    """Turn asset links of older history rows back into asset:// links.

    Rows stored before the history kept asset:// links carry the public asset
    URL (html runs) or a file:// path in the asset root (pdf and plaintext).
    """
    if not text:
        return text
    public = re.compile(
        re.escape(conf.assets_base_url()) + rf"[^\s\"'<>()?]*\?id=({ASSET_ID})"
    )
    text = public.sub(lambda m: f"asset://{m.group(1)}", text)

    root = Path(report_assets_fs.location).as_uri().rstrip("/") + "/"
    if root not in text:
        return text
    local = re.compile(re.escape(root) + r"([^\s\"'<>()]+)")
    names = {unquote(name) for name in local.findall(text)}
    ids = {
        asset.file.name: str(asset.id)
        for asset in _model("ReportAsset").objects.filter(file__in=names)
    }

    def replace(match: re.Match) -> str:
        asset_id = ids.get(unquote(match.group(1)))
        # a deleted asset leaves no server path behind
        return f"asset://{asset_id}" if asset_id else ""

    return local.sub(replace, text)


def base64_encode_assets(text: str) -> List[Dict[str, str]]:
    encoded = []
    for asset_id, asset in _referenced_assets(text).items():
        try:
            with report_assets_fs.open(asset.file.name, "rb") as f:
                content = f.read()
        except (OSError, SuspiciousFileOperation):
            continue
        encoded.append(
            {
                "id": asset_id,
                "name": asset.file.name,
                "file": base64.b64encode(content).decode("ascii"),
            }
        )
    return encoded


def decode_base64_asset(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def rewrite_asset_ids(text: Optional[str], id_map: Dict[str, str]) -> Optional[str]:
    changed = {old: new for old, new in id_map.items() if old != new}
    if not text or not changed:
        return text
    return ASSET_URL_RE.sub(
        lambda m: f"asset://{changed.get(m.group(1), m.group(1))}", text
    )


def _same_content(asset: Any, content: bytes) -> bool:
    try:
        if report_assets_fs.size(asset.file.name) != len(content):
            return False
        with report_assets_fs.open(asset.file.name, "rb") as f:
            return f.read() == content
    except (OSError, SuspiciousFileOperation):
        return False


def _import_assets(assets: Any, written: Optional[List[str]] = None) -> Dict[str, str]:
    """Store the assets of an import bundle.

    Returns old id to stored id. An id that already exists keeps pointing at
    its own file: identical bytes reuse it, anything else gets a new id.
    Stored file names are appended to written so a caller can remove them.
    """
    ReportAsset = _model("ReportAsset")
    written = [] if written is None else written
    id_map: Dict[str, str] = {}
    if not isinstance(assets, list):
        return id_map

    max_bytes = conf.max_asset_bytes()
    for entry in assets:
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) for key in ("id", "name", "file")
        ):
            raise ValidationError("Every asset needs an id, a name and a file")
        name = entry["name"].lstrip("/")
        try:
            given_id = str(uuid.UUID(entry["id"]))
        except ValueError:
            raise ValidationError(f"Asset {name} has an invalid id")
        if not conf.is_allowed_asset(name):
            raise ValidationError(f"Asset {name}: this file type is not allowed")
        if len(entry["file"]) * 3 // 4 > max_bytes:
            raise ValidationError(
                f"Asset {name} is larger than {max_bytes // (1024 * 1024)} MB"
            )
        content = decode_base64_asset(entry["file"])
        if len(content) > max_bytes:
            raise ValidationError(
                f"Asset {name} is larger than {max_bytes // (1024 * 1024)} MB"
            )

        asset_id = given_id
        existing = ReportAsset.objects.filter(id=asset_id).first()
        if existing is not None:
            if _same_content(existing, content):
                id_map[given_id] = asset_id
                continue
            asset_id = str(uuid.uuid4())

        try:
            stored = report_assets_fs.save(name, ContentFile(content), max_length=100)
        except SuspiciousFileOperation:
            raise ValidationError(f"Asset {name} has an invalid path")
        written.append(stored)
        ReportAsset.objects.create(id=asset_id, file=stored)
        id_map[given_id] = asset_id
    return id_map


def _unique_name(model: Type[Model], name: str, max_length: int = 200) -> str:
    for _ in range(20):
        suffix = get_random_string(6, "abcdefghijklmnopqrstuvwxyz")
        candidate = f"{name[: max_length - 7]}_{suffix}"
        if not model.objects.filter(name=candidate).exists():
            return candidate
    raise ValidationError(f"No free name found for {name}")


def _import_base_template(data: Any, overwrite: bool = False) -> Optional[int]:
    if not data:
        return None
    if not isinstance(data, dict):
        raise ValidationError("base_template must be an object")
    name = data.get("name")
    if not name:
        raise ValidationError("base_template is missing 'name' key")
    if data.get("html") is None:
        raise ValidationError("base_template is missing 'html' field")
    html = data["html"]
    if not isinstance(name, str) or len(name) > 200 or not isinstance(html, str):
        raise ValidationError(
            "base_template needs a name of up to 200 characters and html text"
        )

    ReportHTMLTemplate = _model("ReportHTMLTemplate")
    existing = ReportHTMLTemplate.objects.filter(name=name).first()
    if existing is not None and overwrite:
        existing.html = html
        existing.save()
        return existing.pk
    if existing is not None:
        name = _unique_name(ReportHTMLTemplate, name)
    return ReportHTMLTemplate.objects.create(name=name, html=html).pk


def _template_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    ReportTemplate = _model("ReportTemplate")
    fields: Dict[str, Any] = {}

    fields["template_md"] = data["template_md"]
    if not isinstance(fields["template_md"], str):
        raise ValidationError("template_md must be text")

    if "template_css" in data:
        if data["template_css"] is not None and not isinstance(
            data["template_css"], str
        ):
            raise ValidationError("template_css must be text")
        fields["template_css"] = data["template_css"]

    if "type" in data:
        choices = [c[0] for c in ReportTemplate._meta.get_field("type").choices]
        if data["type"] not in choices:
            raise ValidationError(f"type must be one of {', '.join(choices)}")
        fields["type"] = data["type"]

    if "template_variables" in data:
        variables = data["template_variables"]
        if variables is None:
            variables = ""
        if not isinstance(variables, str):
            raise ValidationError("template_variables must be text")
        fields["template_variables"] = variables

    if "depends_on" in data:
        depends_on = data["depends_on"]
        if depends_on is None:
            depends_on = []
        if not isinstance(depends_on, list) or not all(
            isinstance(d, str) and len(d) <= 20 for d in depends_on
        ):
            raise ValidationError(
                "depends_on must be a list of names up to 20 characters"
            )
        reserved = [name for name in depends_on if name in RESERVED_DEPENDENCIES]
        if reserved:
            raise ValidationError(
                f"{', '.join(reserved)} cannot be used as a dependency name"
            )
        fields["depends_on"] = depends_on

    return fields


def _import_report_template(
    data: Any, base_template_id: Optional[int] = None, overwrite: bool = False
) -> Model:
    if not data:
        raise ValidationError("'template' key is required in input")
    if not isinstance(data, dict):
        raise ValidationError("template must be an object")
    name = data.get("name")
    if not name:
        raise ValidationError("template requires a 'name' key")
    if not isinstance(name, str) or len(name) > 200:
        raise ValidationError("template name must be text of up to 200 characters")
    if not data.get("template_md"):
        raise ValidationError("template requires a 'template_md' field")

    fields = _template_fields(data)
    ReportTemplate = _model("ReportTemplate")
    existing = ReportTemplate.objects.filter(name=name).first()
    if existing is not None and overwrite:
        for key, value in fields.items():
            setattr(existing, key, value)
        existing.template_html_id = base_template_id
        existing.save()
        return existing
    if existing is not None:
        name = _unique_name(ReportTemplate, name)
    return ReportTemplate.objects.create(
        name=name, template_html_id=base_template_id, **fields
    )


def import_report_bundle(bundle: Any, overwrite: bool = False) -> Model:
    """Import an export bundle in one transaction.

    Assets go first so their final ids can be written into the template, the
    css and the base template. Files written before a failure are removed.
    """
    if not isinstance(bundle, dict):
        raise ValidationError("The import must be a JSON object")

    written: List[str] = []
    try:
        with transaction.atomic():
            id_map = _import_assets(bundle.get("assets"), written)

            base_template = bundle.get("base_template")
            if isinstance(base_template, dict) and isinstance(
                base_template.get("html"), str
            ):
                base_template = {
                    **base_template,
                    "html": rewrite_asset_ids(base_template.get("html"), id_map),
                }
            template = bundle.get("template")
            if isinstance(template, dict):
                template = {
                    **template,
                    **{
                        key: rewrite_asset_ids(template[key], id_map)
                        for key in ("template_md", "template_css", "template_variables")
                        if isinstance(template.get(key), str)
                    },
                }

            base_template_id = _import_base_template(base_template, overwrite)
            return _import_report_template(template, base_template_id, overwrite)
    except Exception:
        for name in written:
            try:
                report_assets_fs.delete(name)
            except Exception:
                pass
        raise


# ---------------------------------------------------------------------------
# runs

# errors whose text is meant for the template author
USER_ERRORS = (
    ResolveModelException,
    InvalidDBOperationException,
    ObjectDoesNotExist,
    MultipleObjectsReturned,
    FieldError,
    yaml.YAMLError,
    regex.error,
    binascii.Error,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    RecursionError,
)


def report_error_message(error: Exception) -> str:
    if isinstance(error, TemplateError):
        message = error.message or str(error)
        lineno = getattr(error, "lineno", None)
        return f"Line {lineno}: {message}" if lineno else message
    if isinstance(error, ValidationError):
        detail = error.detail
        if isinstance(detail, list):
            return " ".join(str(item) for item in detail)
        return str(detail)
    if isinstance(error, DjangoValidationError):
        return " ".join(error.messages)
    if isinstance(error, USER_ERRORS):
        return str(error)

    # file system and database errors can carry paths and internals
    logger.error(f"reporting: report generation failed: {error!r}")
    return "The report could not be generated. The server log has the details."


def _history(
    template: Model,
    user: Optional["User"],
    schedule: Optional[Model] = None,
    report_data: str = "",
    error: Optional[str] = None,
):
    return _model("ReportHistory").objects.create(
        report_template=template,
        report_data=report_data,
        error_data=error,
        run_by=user.username if user else "system",
        user=user,
        schedule=schedule,
    )


def run_report(
    template: Model,
    dependencies: Optional[Dict[str, Any]] = None,
    format: str = "html",
    user: Optional["User"] = None,
    schedule: Optional[Model] = None,
) -> Tuple[Union[str, bytes, None], Optional[str], Model]:
    """Render, convert and record one run. Never raises for report errors.

    Returns (output, error, history): text for html and plaintext, bytes for
    pdf. Exactly one history row is written per run.
    """
    # a failed query must not break an outer transaction the history row needs
    savepoint = transaction.atomic() if connection.in_atomic_block else nullcontext()
    try:
        with savepoint:
            if format not in REPORT_FORMATS:
                raise ValueError("Report format is incorrect.")
            html, _ = generate_html(
                template=template.template_md,
                template_type=template.type,
                css=template.template_css or "",
                html_template=template.template_html_id,
                variables=template.template_variables,
                dependencies=dependencies or {},
                user=user,
            )
            # history keeps the asset:// links, so it can be shown in any format
            output = normalize_asset_url(html, format)
            if format == "pdf":
                output = generate_pdf(output)
    except Exception as error:
        message = report_error_message(error)
        return None, message, _history(template, user, schedule, error=message)

    return output, None, _history(template, user, schedule, report_data=html)


def build_report_link(id: int, format: str) -> str:
    return f"{settings.CORS_ORIGIN_WHITELIST[0]}/reports/history/{id}/?format={format}"


def encode_attachment(output: Union[str, bytes, None], format: str) -> Optional[str]:
    """Report output in a JSON-safe form for the email task: pdf as base64."""
    if output is None:
        return None
    if format == "pdf" or isinstance(output, bytes):
        return base64.b64encode(output).decode("ascii")
    return output


def queue_report_email(
    template: Model,
    history: Model,
    output: Union[str, bytes, None],
    format: str,
    recipients: List[str],
    email_settings: Any,
) -> None:
    from .tasks import email_report

    if not isinstance(email_settings, dict):
        email_settings = {}
    email_report.delay(
        template_name=template.name,
        report_link=build_report_link(history.id, format),
        recipients=recipients,
        attachment=encode_attachment(output, format),
        attachment_type=format,
        subject=email_settings.get("subject"),
        body=email_settings.get("body"),
        attachment_name=email_settings.get("attachment_name"),
        attachment_extension=email_settings.get("attachment_extension"),
        include_report_link=email_settings.get("include_report_link"),
    )


def run_refusal(user: "User") -> Optional[str]:
    """Why a schedule may not run as user, None when it may."""
    if not user.is_active:
        return f"This schedule runs as {user.username}, who is disabled"
    if user.block_dashboard_login:
        return (
            f"This schedule runs as {user.username}, who is blocked from "
            "dashboard login"
        )
    if not can_view_reports(user):
        return f"This schedule runs as {user.username}, who may no longer view reports"
    return None


def run_scheduled_report(
    schedule: Model, user: Optional["User"] = None
) -> Tuple[Model, Optional[str]]:
    """Run a schedule with its owner's role scope, or with user's on demand.

    Schedules without an owner run unscoped. A user who may no longer run
    reports gets a failed run and no email.
    """
    template = schedule.report_template
    if user is None:
        user = getattr(schedule, "owner", None)

    error = run_refusal(user) if user is not None else None
    if error:
        logger.info(f"reporting: schedule {schedule.pk} skipped: {error}")
        output, history = None, _history(template, user, schedule, error=error)
    else:
        output, error, history = run_report(
            template, schedule.dependencies, schedule.format, user, schedule
        )

    schedule.last_run = djangotime.now()
    schedule.save(update_fields=["last_run"])

    if schedule.send_report_email and error is None:
        queue_report_email(
            template,
            history,
            output,
            schedule.format,
            schedule.email_recipients,
            schedule.email_settings,
        )

    return history, error
