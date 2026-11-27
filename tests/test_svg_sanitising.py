"""Stored SVG is rebuilt from an allowlist: what draws stays, what runs,
loads or links elsewhere goes."""

import pytest

from mosp.security.svg import SvgError, sanitise_svg

OPEN = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'


def _clean(body):
    return sanitise_svg(OPEN + body + "</svg>")


def test_a_drawing_keeps_its_shapes_text_and_annotations():
    stored = _clean(
        '<g data-id="A" aria-label="Start"><path d="M0 0L1 1" fill="#fff"/></g>'
        '<defs><marker id="m"><path d="M0 0"/></marker></defs>'
        '<use href="#m"/><use xlink:href="#m"/><text>Go</text>'
    )
    assert (
        '<g data-id="A" aria-label="Start"><path d="M0 0L1 1" fill="#fff" /></g>'
        in stored
    )
    assert '<use href="#m" />' in stored
    assert '<use xlink:href="#m" />' in stored
    assert "<text>Go</text>" in stored


@pytest.mark.parametrize(
    "body,gone",
    [
        ("<script>alert(1)</script>", "script"),
        (
            '<foreignObject><div xmlns="http://www.w3.org/1999/xhtml"/></foreignObject>',
            "foreignObject",
        ),
        ('<image href="https://elsewhere.example/x.png"/>', "image"),
        ('<rect onclick="alert(1)"/>', "onclick"),
        ('<animate attributeName="href" to="javascript:alert(1)"/>', "animate"),
        ('<use href="https://elsewhere.example/sprite.svg#x"/>', "elsewhere"),
        ('<rect fill="url(https://elsewhere.example/x)"/>', "elsewhere"),
        ('<rect style="background:url(https://elsewhere.example/x)"/>', "elsewhere"),
        # A CSS escape spells "url(" without the letters: u\72l is url.
        ('<rect fill="u\\72l(https://elsewhere.example/x)"/>', "elsewhere"),
        ('<rect filter="\\75rl(https://elsewhere.example/x#f)"/>', "elsewhere"),
        ('<rect stroke="ur\\6c (https://elsewhere.example/x)"/>', "elsewhere"),
        ('<rect class="javascript:x"/>', "javascript"),
        ('<rect xmlns="" class="outside"/>', "outside"),
        ("<style>@import url(https://elsewhere.example/x.css);</style>", "import"),
        ("<style>rect { fill: red }<g/></style>", "style"),
        ('<h:p xmlns:h="http://www.w3.org/1999/xhtml">x</h:p>', "xhtml"),
    ],
)
def test_what_runs_loads_or_leaves_the_document_is_dropped(body, gone):
    assert gone not in _clean(body)


def test_an_annotation_keeps_a_backslash_it_cannot_act_on():
    # data-* and aria-* are text the drawing tools keep for themselves.
    stored = _clean('<rect aria-label="C:\\reports" data-id="a\\b" fill="red"/>')
    assert 'aria-label="C:\\reports"' in stored
    assert 'data-id="a\\b"' in stored
    assert 'fill="red"' in stored


def test_safe_styles_and_same_document_references_stay():
    stored = _clean(
        '<style>rect { fill: url(#g) }</style><rect style="fill:url( #g )"/>'
    )
    assert "<style>rect { fill: url(#g) }</style>" in stored
    assert 'style="fill:url( #g )"' in stored


def test_a_link_is_unwrapped_and_its_drawing_kept():
    stored = _clean('<a href="https://elsewhere.example/"><rect width="1"/>tail</a>')
    assert "<a" not in stored and "elsewhere" not in stored
    assert '<rect width="1" />tail' in stored


def test_text_keeps_its_order_around_dropped_children():
    stored = _clean("<text>a<tspan>b</tspan>c<script>x</script>d</text>")
    assert stored.endswith("<text>a<tspan>b</tspan>cd</text></svg>")
    assert _clean("<text><script>x</script>only</text>").endswith(
        "<text>only</text></svg>"
    )


@pytest.mark.parametrize(
    "document,refusal",
    [
        ("<svg", "not well-formed"),
        ("<html/>", "Expected an SVG document"),
        ('<svg xmlns="http://example.invalid/"/>', "Expected an SVG document"),
    ],
)
def test_anything_but_an_svg_document_is_refused(document, refusal):
    with pytest.raises(SvgError, match=refusal):
        sanitise_svg(document)


def test_the_size_bound_is_the_callers():
    drawing = OPEN + "<desc>" + "x" * 2048 + "</desc></svg>"
    with pytest.raises(SvgError, match="not well-formed"):
        sanitise_svg(drawing, max_bytes=1024)
    assert sanitise_svg(drawing, max_bytes=4096).startswith("<svg")
