# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime
import io
import json
import os
import time
from unittest.mock import patch

import pytest
import yaml
from django.test import override_settings
from jinja2 import TemplateSyntaxError
from jinja2.sandbox import SecurityError
from markupsafe import Markup

from discovery.models import Scan
from reporting.custom_filters import as_tz, local_ips
from reporting.markdown_ext import convert_markdown
from reporting.utils import (
    DatabaseCSV,
    DatabaseJSON,
    DatabaseRow,
    DatabaseText,
    InvalidDBOperationException,
    RenderLimitExceeded,
    _to_csv,
    check_lookup_path,
    env,
    generate_chart,
    generate_pdf,
    parse_variables,
    plaintext_env,
    process_chart_variables,
    process_data_sources,
    render_with_limits,
    report_error_message,
    report_url_fetcher,
)
from vault.models import Document


def png_bytes():
    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (2, 2), "red").save(buffer, "PNG")
    return buffer.getvalue()


def render(source, **context):
    return render_with_limits(env.from_string(source), context)


# rendering, Markdown and Jinja syntax


def test_markdown_output():
    html = convert_markdown(
        "# Title {: .big }\n\nline one\nline two\n\n~~S intro~~\ntext\n~~/S~~\n\n"
        "| a | b |\n|---|---|\n| 1 | 2 |\n\n```\n{{ value }}\n```\n"
    )
    assert '<h1 class="big">Title</h1>' in html
    assert "line one<br />" in html
    assert '<section id="intro">' in html
    assert "<table>" in html and "<thead>" in html and "<tbody>" in html
    assert "<pre><code>{{ value }}" in html


def test_markdown_keeps_jinja_tags():
    html = convert_markdown(
        "{% for item in items %}\n\n- {{ item }}\n\n{% endfor %}\n\n"
        "text {% if a > b %}more{% endif %}\n\n```\n{% if a > b %}x{% endif %}\n```"
    )
    assert "{% for item in items %}" in html
    assert "{% endfor %}" in html
    assert "{% if a > b %}more{% endif %}" in html
    assert "{% if a > b %}x{% endif %}" in html
    assert "ulrmm-jinja" not in html
    assert render(html, items=["one", "two"], a=1, b=0).count("<li>") == 2


def test_markdown_jinja_tags_stay_in_tables_and_paragraphs():
    # a loop inside a pipe table keeps its rows in the table
    html = convert_markdown(
        "| Host | OS |\n|---|---|\n{% for a in agents %}\n"
        "| {{ a.h }} | {{ a.o }} |\n{% endfor %}"
    )
    assert html.count("<table>") == 1 and "<p>" not in html
    assert "<td>{% for a in agents %}</td>\n<td></td>" in html
    assert "<td>{{ a.h }}</td>\n<td>{{ a.o }}</td>" in html
    rendered = render(html, agents=[{"h": "h1", "o": "o1"}, {"h": "h2", "o": "o2"}])
    assert rendered.index("<td>h2</td>") < rendered.index("</tbody>")

    # tag lines next to text stay in the paragraph, list markers stay text
    html = convert_markdown("{% for i in range(2) %}\n* item {{ i }}\n{% endfor %}")
    assert (
        html
        == "<p>{% for i in range(2) %}<br />\n* item {{ i }}<br />\n{% endfor %}</p>"
    )
    assert render(html).startswith("<p><br />\n* item 0<br />\n")
    html = convert_markdown("| Host |\n|---|\n{% for i in x %}| {{ i }} |{% endfor %}")
    assert html.startswith("<p>| Host |<br />")
    assert html.endswith("{% for i in x %}| {{ i }} |{% endfor %}</p>")


def test_markdown_has_no_state_between_calls():
    first = convert_markdown("Term\n: Definition\n\n[^1]")
    assert convert_markdown("Term\n: Definition\n\n[^1]") == first


def test_comments_extensions_and_escaping():
    assert render("a{= hidden =}b") == "ab"
    assert render("{# shown #}") == "{# shown #}"
    assert (
        render(
            "{% set ns = namespace(items=[]) %}{% for i in range(5) %}"
            "{% if i == 3 %}{% break %}{% endif %}{% do ns.items.append(i) %}"
            "{% endfor %}{{ ns.items|join(',') }}"
        )
        == "0,1,2"
    )
    # what the author wrote prints as it is, database text is escaped
    assert render("{{ value }}", value="<b>x</b>") == "<b>x</b>"
    assert render("{{ value }}", value=["<b>", {"k": "v"}]) == "['<b>', {'k': 'v'}]"
    assert render("{{ '<b>' ~ value }}{{ {'b': 1, 'a': 2}|dictsort }}", value="x") == (
        "<b>x[('a', 2), ('b', 1)]"
    )
    assert render("{{ value }}", value=Markup("<b>x</b>")) == "<b>x</b>"
    assert render("{{ value }}", value=DatabaseText("<b>&")) == "&lt;b&gt;&amp;"
    assert render("{{ value|safe }}", value=DatabaseText("<b>")) == "<b>"
    assert render("{{ value|e }}", value=DatabaseText("<b>")) == "&lt;b&gt;"
    assert render("{{ row.name }}{{ row['name'] }}", row=DatabaseRow(name="<i>")) == (
        "&lt;i&gt;&lt;i&gt;"
    )
    data = json.dumps([{"name": "</script><b>&'x'"}])
    rendered = render("{{ value }}", value=DatabaseJSON(data))
    assert "<" not in rendered and "&" not in rendered and "'" not in rendered
    assert json.loads(rendered) == json.loads(data)
    assert render("{{ value }}", value=DatabaseCSV('a,b\n"<x>",&\n')) == (
        'a,b\n"&lt;x&gt;",&amp;\n'
    )
    plain = plaintext_env.from_string("{{ value }}{{ db }}")
    assert render_with_limits(plain, {"value": "<b>", "db": DatabaseText("<i>")}) == (
        "<b><i>"
    )


def test_syntax_error_has_line_number():
    with pytest.raises(TemplateSyntaxError) as error:
        env.parse("line\n{% if x %}\nno end")
    assert report_error_message(error.value).startswith("Line ")


def test_globals_and_filters():
    assert sorted(env.globals) == sorted(
        [
            "range",
            "dict",
            "lipsum",
            "cycler",
            "joiner",
            "namespace",
            "datetime",
            "ZoneInfo",
            "re",
        ]
    )
    names = set(vars(env.globals["datetime"]))
    assert {"datetime", "timedelta", "timezone", "UTC"} <= names
    assert not any(name.startswith("_") for name in names)

    value = datetime.datetime(2026, 1, 15, 12, 0, tzinfo=datetime.timezone.utc)
    assert as_tz(value, "Europe/Berlin") == "Jan 15 2026, 01:00 PM"
    assert as_tz(value, "Europe/Berlin", "%H:%M") == "13:00"
    with pytest.raises(ValueError):
        as_tz(value.replace(tzinfo=None), "Europe/Berlin")
    assert (
        render(
            "{{ (value.astimezone(ZoneInfo('America/Los_Angeles'))).strftime('%H') }}",
            value=value,
        )
        == "04"
    )


def test_re_global():
    assert render("{{ re.sub('[0-9]+', '#', 'a1b22') }}") == "a#b#"
    assert render("{{ re.subn('b', 'c', 'abb') }}") == "('acc', 2)"
    assert render("{{ re.findall('[0-9]+', 'a1b22') }}") == "['1', '22']"
    assert render("{{ re.match('(a)(b)', 'abc').group(2) }}") == "b"
    assert render("{{ re.search('B', 'abc', re.I).span() }}") == "(1, 2)"
    assert render("{{ re.fullmatch('a.c', 'abc') is not none }}") == "True"
    assert render("{{ re.split(',', 'a,b,c', 1) }}") == "['a', 'b,c']"
    assert render("{{ re.escape('a.b') }}") == "a\\.b"
    assert (
        render(
            "{% set p = re.compile('(?P<n>[0-9]+)', re.M) %}"
            "{% for m in p.finditer('1 22') %}{{ m.group('n') }};{% endfor %}"
            "{{ p.pattern }} {{ p.groups }}"
        )
        == "1;22;(?P<n>[0-9]+) 1"
    )
    assert render("{{ re.purge() }}{{ re.error is defined }}") == "NoneTrue"
    assert render("{{ re.Pattern is defined and re.Match is defined }}") == "True"
    assert render("{{ re.IGNORECASE == re.I and re.NOFLAG == 0 }}") == "True"
    assert render("{{ re.I }} {{ re.A|int }}") == "re.IGNORECASE 256"
    assert render("{{ re.compile('x') }} {{ re.compile('x').flags }}") == (
        "re.compile('x') 32"
    )
    assert render("{{ re.compile('x', re.I + re.M) }}") == (
        "re.compile('x', re.IGNORECASE|re.MULTILINE)"
    )
    assert render("{{ re.findall('[a-z]', 'aB', re.I) }}") == "['a', 'B']"
    assert render("{{ re.match('a.b', 'a\\nb', re.S) is not none }}") == "True"

    with pytest.raises(SecurityError):
        render("{{ re.match('a', 'a').re.match('a') }}")
    with pytest.raises(SecurityError):
        render("{{ re.compile(p) }}", p="a" * 20_000)
    with pytest.raises(SecurityError):
        render("{{ re.compile('a')._compiled.match('a') }}")
    with override_settings(REPORTING_MAX_OUTPUT_MB=1), pytest.raises(SecurityError):
        render("{{ re.sub('a', 'b' * 1000, 'a' * 2000) }}")

    with pytest.raises(Exception) as error:
        render("{{ re.compile('(') }}")
    assert report_error_message(error.value) == "missing ) at position 1"

    # a catastrophic pattern stops at the render time limit
    with override_settings(REPORTING_RENDER_TIMEOUT=0.5):
        started = time.monotonic()
        with pytest.raises(RenderLimitExceeded):
            render("{{ re.match('(a|aa)+$', 'a' * 5000 + 'b') }}")
        assert time.monotonic() - started < 10


def test_local_ips():
    wmi = {
        "network_config": [
            [
                {"Caption": "x"},
                {"IPAddress": ["10.0.0.5", "fe80::1", 7, "192.168.1.2"]},
            ],
            [{"IPAddress": None}],
        ]
    }
    assert local_ips(wmi) == ["10.0.0.5", "192.168.1.2"]
    assert local_ips({}) == []
    assert local_ips({"network_config": "broken"}) == []
    assert local_ips(None) == []


# sandbox


def test_sandbox_refuses_private_and_credential_access():
    with pytest.raises(SecurityError):
        render("{{ value.__class__.__mro__ }}", value="x")
    for model in (Scan, Document):
        instance = model()
        assert not env.is_safe_attribute(instance, "pk", None)
    for model, path in ((Scan, "snmp_community"), (Document, "body")):
        with pytest.raises(InvalidDBOperationException):
            check_lookup_path(model, path)


def test_sandbox_limits():
    with pytest.raises(SecurityError):
        render("{{ 'x' * 10 ** 9 }}")
    with pytest.raises(SecurityError):
        render("{{ 3 ** 1000000 }}")
    assert render("{{ 'ab' * 2 }}{{ 2 ** 10 }}") == "abab1024"

    with override_settings(REPORTING_RENDER_TIMEOUT=0.5):
        started = time.monotonic()
        with pytest.raises(RenderLimitExceeded):
            render(
                "{% set r = range(100000) %}{% for a in r %}{% for b in r %}"
                "{% endfor %}{% endfor %}"
            )
        assert time.monotonic() - started < 10

    with override_settings(REPORTING_MAX_OUTPUT_MB=0):
        with pytest.raises(RenderLimitExceeded):
            render("x")

    # the guard keeps loop helpers working
    assert (
        render(
            "{% for x in items %}{{ loop.index }}/{{ loop.length }}{% if loop.last %}!{% endif %} {% endfor %}",
            items="abc",
        )
        == "1/3 2/3 3/3! "
    )


# variables YAML


def test_now_tag():
    now = datetime.datetime.now(datetime.timezone.utc)
    data = parse_variables(
        "now: !now\nback: !now days=-30\nbanana: !now banana\n"
        "units: [!now weeks=1, !now hours=-2, !now minutes=3, !now seconds=-4, !now microseconds=5]"
    )
    assert abs(data["now"] - now) < datetime.timedelta(seconds=5)
    assert abs(data["back"] - (now - datetime.timedelta(days=30))) < datetime.timedelta(
        seconds=5
    )
    assert abs(data["banana"] - now) < datetime.timedelta(seconds=5)
    for value, delta in zip(
        data["units"],
        (
            datetime.timedelta(weeks=1),
            datetime.timedelta(hours=-2),
            datetime.timedelta(minutes=3),
            datetime.timedelta(seconds=-4),
            datetime.timedelta(microseconds=5),
        ),
    ):
        assert abs(value - (now + delta)) < datetime.timedelta(seconds=5)

    with pytest.raises(yaml.YAMLError) as error:
        parse_variables("x: !now days=")
    assert "whole number" in str(error.value)

    # offsets that are not exactly unit=number are ignored, as before
    data = parse_variables(
        "a: !now days=+5\nb: !now days = 5\nc: !now days=1.5\nd: !now days=abc\n"
        "e: !now Days=2"
    )
    for value in data.values():
        assert abs(value - now) < datetime.timedelta(seconds=5)


def test_placeholders_are_values_not_yaml():
    data = parse_variables(
        "a: {{name}}\nb: \"pre {{ name }} post\"\nc: {{count}}\nd: '{{ name}}'\n"
        'e: "{{missing}}"\nf: {{evil}}\ng: "{{evil}}"\nh: !now days={{days}}',
        {
            "name": 'Acme "Corp"',
            "count": 5,
            "evil": "x\ndata_sources:\n  a: {model: agent}",
            "days": -2,
        },
    )
    assert data["a"] == 'Acme "Corp"'
    assert data["b"] == 'pre Acme "Corp" post'
    assert data["c"] == 5
    assert data["d"] == 'Acme "Corp"'
    assert data["e"] == "{{missing}}"
    assert data["f"] == data["g"] == "x\ndata_sources:\n  a: {model: agent}"
    assert isinstance(data["h"], datetime.datetime)
    assert "data_sources" not in data

    assert parse_variables("") == {}
    assert parse_variables(None) == {}
    with pytest.raises(ValueError):
        parse_variables("- a\n- b")
    with pytest.raises(ValueError):
        parse_variables({"a": 1})


# data sources and charts glue


def test_data_sources_without_queries_stay():
    assert process_data_sources({"a": 1}) == {"a": 1}
    assert process_data_sources({"data_sources": "x"}) == {"data_sources": "x"}
    with patch("reporting.utils.build_queryset", return_value=[{"id": 1}]) as build:
        result = process_data_sources(
            {"data_sources": {"one": {"model": "agent"}, "two": "named"}}, 5
        )
    assert result["data_sources"] == {"one": [{"id": 1}], "two": "named"}
    assert build.call_args.kwargs["limit"] == 5


def test_chart_variables():
    for variables in ({}, {"charts": "x"}, {"charts": {"c": {}}}):
        assert process_chart_variables(json.loads(json.dumps(variables))) == variables

    missing = {"charts": {"c": {"options": {"data_frame": "data_sources.none"}}}}
    assert process_chart_variables(json.loads(json.dumps(missing))) == missing
    across_list = {
        "data_sources": {"rows": [{"a": 1}]},
        "charts": {"c": {"options": {"data_frame": "data_sources.rows.a"}}},
    }
    assert process_chart_variables(json.loads(json.dumps(across_list))) == across_list

    empty = {
        "data_sources": {"rows": []},
        "charts": {"c": {"options": {"data_frame": "data_sources.rows"}}},
    }
    assert process_chart_variables(empty)["charts"] == {}

    rows = [{"x": 1, "y": 2}]
    variables = {
        "data_sources": {"rows": rows},
        "charts": {
            "c": {
                "chartType": "bar",
                "outputType": "image",
                "options": {"data_frame": "data_sources.rows", "x": "x"},
            }
        },
    }
    with patch("reporting.utils.generate_chart", return_value="<svg/>") as chart:
        result = process_chart_variables(variables)
    chart.assert_called_once_with(
        type="bar",
        format="image",
        options={"data_frame": rows, "x": "x"},
        traces=None,
        layout=None,
    )
    assert result["charts"]["c"] == "<svg/>"


def test_generate_chart_html_uses_own_script():
    with override_settings(REPORTING_BASE_URL="https://api.example.com"):
        html = generate_chart(
            "bar", "html", {"data_frame": [{"x": "a", "y": 1}], "x": "x", "y": "y"}
        )
    assert isinstance(html, Markup)
    assert "plotly" in html
    assert 'src="https://api.example.com/static/reporting/js/plotly-' in html
    assert "cdn" not in html


def test_generate_chart_image_has_no_network():
    with patch("kaleido.calc_fig_sync", return_value=b"<svg>pie</svg>") as kaleido:
        svg = generate_chart(
            "pie",
            "image",
            {"data_frame": [{"n": "a", "v": 1}], "names": "n", "values": "v"},
        )
    assert svg == "<svg>pie</svg>"
    assert kaleido.call_args.kwargs["kopts"] == {"mathjax": False}
    assert generate_chart("bar", "other", {}) is None


def test_generate_chart_refusals():
    for chart_type in (
        "__class__",
        "set_mapbox_access_token",
        "scatter_geo",
        "scatter_mapbox",
        "imshow",
        "choropleth",
    ):
        with pytest.raises(ValueError, match="Invalid chart type"):
            generate_chart(chart_type, "image", {})
    for traces, layout in (
        (None, {"images": [{"source": "x.png"}]}),
        (None, {"title": {"text": "see http://169.254.169.254/"}}),
        ({"marker": {"color": "//evil"}}, None),
        (None, {"geo": {"scope": "europe"}}),
    ):
        with pytest.raises(ValueError):
            generate_chart("bar", "image", {"data_frame": [{"x": 1}]}, traces, layout)


def test_csv_helper():
    rows = [
        {"id": 1, "hostname": "a", "os": None},
        {"id": 2, "hostname": "b,c", "os": "x"},
    ]
    assert _to_csv(rows, None) == 'hostname,os\na,\n"b,c",x\n'
    assert _to_csv(rows, {"hostname": "Hostname"}).startswith("Hostname,os\n")
    assert _to_csv({"id": 1, "a": 2}, None) == "a\n2\n"


# PDF


def test_pdf_and_url_fetcher(tmp_path):
    root = tmp_path / "assets"
    root.mkdir()
    (root / "logo.png").write_bytes(png_bytes())
    outside = tmp_path / "outside.png"
    outside.write_bytes(png_bytes())
    os.symlink(outside, root / "link.png")

    with override_settings(REPORTING_ASSETS_BASE_PATH=str(root)):
        assert generate_pdf("<p>hello</p>").startswith(b"%PDF")
        fetcher = report_url_fetcher()
        for url in ((root / "logo.png").as_uri(), "data:text/plain,hi"):
            fetcher.fetch(url).close()
        for url in (
            "file:///etc/hostname",
            outside.as_uri(),
            (root / "link.png").as_uri(),
            (root / ".." / "outside.png").as_uri(),
            root.as_uri(),
            "http://127.0.0.1/",
            "https://example.com/x.png",
            "ftp://example.com/x",
        ):
            with pytest.raises(ValueError):
                fetcher.fetch(url)

        from weasyprint.urls import URLFetcher

        with patch.object(
            URLFetcher, "fetch", autospec=True, side_effect=URLFetcher.fetch
        ) as fetch:
            pdf = generate_pdf(
                f'<img src="{(root / "logo.png").as_uri()}">'
                '<img src="file:///etc/hostname">'
                f'<link rel="attachment" href="{outside.as_uri()}">'
                '<link rel="stylesheet" href="http://127.0.0.1:9/x.css">'
                '<a rel="attachment" href="file:///etc/passwd">x</a>',
                css="body { background: url(http://127.0.0.1:9/bg.png) }",
            )
        assert pdf.startswith(b"%PDF")
        assert {call.args[1] for call in fetch.call_args_list} == {
            (root / "logo.png").as_uri()
        }


def test_copy_plotly_js(tmp_path):
    import plotly

    from reporting.utils import copy_plotly_js

    old = tmp_path / "reporting" / "js" / "plotly-0.0.1.min.js"
    old.parent.mkdir(parents=True)
    old.write_text("old")
    with override_settings(STATICFILES_DIRS=[str(tmp_path)]):
        target = copy_plotly_js()
    assert target.name == f"plotly-{plotly.__version__}.min.js"
    assert target.stat().st_size > 1_000_000
    assert not old.exists()
