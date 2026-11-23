"""Rebuild browser-rendered SVG from an allowlist before it is stored.

An SVG drawing sent to the application (a diagram the browser rendered with
bpmn-js or Mermaid, say) is whatever the sender chose to send. The
application stores only what this module rebuilds from it: the elements and attributes that draw shapes,
paths, text, markers, gradients and filters. Everything else is dropped with
its content: scripts, foreign objects, embedded documents, images, links to
other documents, animation (which can rewrite an attribute such as ``href``
after sanitising), event handlers, and any attribute outside the allowlist.
References stay inside the document (``#id``). Style sheets and ``style``
attributes are kept only when they load nothing: no ``url()`` other than a
same-document ``#id``, no ``@import``, no escapes that could spell either.

The result is serialised again from the tree, so text and attribute values
are escaped by the serialiser, not copied through. Pages should still display
stored SVG as an image (``<img>``), which runs no script whatever the markup
holds; this module is the second lock.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from mosp.security.regex import scan_pattern
from mosp.security.xml import MAX_DOCUMENT_BYTES, parse_untrusted_xml

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
XML_NS = "http://www.w3.org/XML/1998/namespace"

_ELEMENTS = frozenset(
    {
        "svg",
        "g",
        "defs",
        "symbol",
        "use",
        "path",
        "rect",
        "circle",
        "ellipse",
        "line",
        "polyline",
        "polygon",
        "text",
        "tspan",
        "marker",
        "clipPath",
        "mask",
        "pattern",
        "linearGradient",
        "radialGradient",
        "stop",
        "title",
        "desc",
        "style",
        "filter",
        "feGaussianBlur",
        "feOffset",
        "feBlend",
        "feFlood",
        "feComposite",
        "feMerge",
        "feMergeNode",
        "feColorMatrix",
        "feDropShadow",
    }
)
# Links are unwrapped: their drawing is kept, the link is not.
_UNWRAPPED = frozenset({"a"})

_ATTRIBUTES = frozenset(
    {
        "id",
        "class",
        "style",
        "role",
        "version",
        "viewBox",
        "preserveAspectRatio",
        "width",
        "height",
        "x",
        "y",
        "x1",
        "y1",
        "x2",
        "y2",
        "cx",
        "cy",
        "r",
        "rx",
        "ry",
        "dx",
        "dy",
        "d",
        "points",
        "transform",
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-opacity",
        "stroke-dasharray",
        "stroke-dashoffset",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-miterlimit",
        "opacity",
        "color",
        "visibility",
        "display",
        "font-family",
        "font-size",
        "font-weight",
        "font-style",
        "font-variant",
        "letter-spacing",
        "word-spacing",
        "text-anchor",
        "text-decoration",
        "dominant-baseline",
        "alignment-baseline",
        "baseline-shift",
        "writing-mode",
        "clip-path",
        "clip-rule",
        "mask",
        "filter",
        "marker-start",
        "marker-mid",
        "marker-end",
        "markerWidth",
        "markerHeight",
        "markerUnits",
        "refX",
        "refY",
        "orient",
        "offset",
        "stop-color",
        "stop-opacity",
        "gradientUnits",
        "gradientTransform",
        "patternUnits",
        "patternContentUnits",
        "patternTransform",
        "clipPathUnits",
        "maskUnits",
        "maskContentUnits",
        "filterUnits",
        "primitiveUnits",
        "stdDeviation",
        "in",
        "in2",
        "result",
        "mode",
        "operator",
        "k1",
        "k2",
        "k3",
        "k4",
        "values",
        "type",
        "flood-color",
        "flood-opacity",
        "pointer-events",
        "shape-rendering",
        "text-rendering",
        "vector-effect",
        "overflow",
        "href",
        f"{{{XLINK_NS}}}href",
        f"{{{XML_NS}}}space",
    }
)
# Inert annotations Mermaid and bpmn-js add for their own lookups.
_ANNOTATION = scan_pattern(r"(?:data|aria)-[a-z0-9-]{1,64}")

# Anything in CSS that could load a resource or hide such text from this check.
_UNSAFE_CSS = scan_pattern(
    r"\\|<|@import|expression\s*\(|javascript:|behavior\s*:|-moz-binding"
    r"|url\s*\((?!\s*['\"]?\s*#)",
    re.IGNORECASE,
)
# A same-document reference: "#" and an XML name.
_FRAGMENT = scan_pattern(r"#[A-Za-z_][\w.:-]{0,255}")
_CONTROL = scan_pattern(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class SvgError(ValueError):
    """The document is not an SVG drawing the application stores."""


def _local(tag: str) -> tuple[str | None, str]:
    if tag.startswith("{"):
        namespace, _, local = tag[1:].partition("}")
        return namespace, local
    return None, tag


def _safe_value(name: str, value: str) -> bool:
    if _CONTROL.search(value) or "javascript:" in value.lower():
        return False
    if name in {"href", f"{{{XLINK_NS}}}href"}:
        return bool(_FRAGMENT.fullmatch(value.strip()))
    if name == "style" or "url(" in value.lower():
        return not _UNSAFE_CSS.search(value)
    return True


def _append_text(element: ET.Element, text: str | None) -> None:
    """Add text after the element's last child (or as its text when it has none)."""
    if not text:
        return
    if len(element):
        last = element[-1]
        last.tail = (last.tail or "") + text
    else:
        element.text = (element.text or "") + text


def _copy_children(source: ET.Element, element: ET.Element) -> None:
    for child in source:
        for kept in _copy(child):
            element.append(kept)
        # Text after a child belongs to its parent, whether or not the child
        # was kept (an SVG <text> holds mixed content).
        _append_text(element, child.tail)


def _copy(source: ET.Element) -> list[ET.Element]:
    """The safe rendering of ``source``: one element, its children when the
    element itself is unwrapped, or nothing."""
    namespace, local = _local(source.tag)
    if namespace != SVG_NS:
        return []
    if local in _UNWRAPPED:
        holder = ET.Element(source.tag)
        _copy_children(source, holder)
        return list(holder)
    if local not in _ELEMENTS:
        return []
    if local == "style":
        css = source.text or ""
        if len(source) or _UNSAFE_CSS.search(css) or _CONTROL.search(css):
            return []
    element = ET.Element(source.tag)
    for name, value in source.attrib.items():
        if (name in _ATTRIBUTES or _ANNOTATION.fullmatch(name)) and _safe_value(
            name, value
        ):
            element.set(name, value)
    element.text = source.text
    _copy_children(source, element)
    return [element]


def sanitise_svg(document: str, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> str:
    """The stored form of a browser-rendered SVG, or SvgError.

    ``max_bytes`` bounds the document as parse_untrusted_xml does.
    """
    try:
        root = parse_untrusted_xml(document, max_bytes=max_bytes)
    except ET.ParseError as exc:
        raise SvgError("SVG is not well-formed XML") from exc
    if root.tag != f"{{{SVG_NS}}}svg":
        raise SvgError("Expected an SVG document")
    # The root is an SVG element on the allowlist, so it is kept.
    (drawing,) = _copy(root)
    ET.register_namespace("", SVG_NS)
    ET.register_namespace("xlink", XLINK_NS)
    return ET.tostring(drawing, encoding="unicode")
