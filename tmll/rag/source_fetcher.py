"""Fetch a retrieved document's source page live, at answer time.

The knowledge index intentionally stores only short pointer text (see
rag/knowledge/) plus citation metadata -- it does not hold permanent
copies of third-party pages. When a question actually retrieves a
document and the full source would help ground the answer, this module
fetches that one page over HTTP, extracts its visible text, and hands it
to the prompt builder for that single request only. Nothing here is
written to disk or to the vector index, and only the documents actually
retrieved for one question are ever fetched -- never the whole
knowledge base.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from html.parser import HTMLParser

import requests

from rag.schemas import RetrievedDocument

DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_CHARS = 6000
DEFAULT_MAX_DOCUMENTS_TO_FETCH = 3
USER_AGENT = "Mozilla/5.0 (compatible; TMLL-RAG-source-fetch/1.0)"


class _TextExtractor(HTMLParser):
    """Site-agnostic HTML-to-text conversion.

    This strips markup and collapses whitespace; it does not drop,
    reorder, or rewrite any visible text, so it is not a summarizer.
    """

    _BLOCK_TAGS = {
        "p", "div", "section", "article", "li", "tr",
        "h1", "h2", "h3", "h4", "h5", "h6", "pre", "br",
    }
    _SKIPPED_TAGS = {"script", "style", "nav", "header", "footer"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIPPED_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in self._BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIPPED_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._chunks.append(data)

    def get_text(self) -> str:
        text = "".join(self._chunks)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
        return text.strip()


def fetch_source_text(
    url: str,
    max_chars: int = DEFAULT_MAX_CHARS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> str | None:
    """Fetch one URL and return its extracted visible text, or None.

    The result is capped at max_chars (with a truncation marker) and is
    request-scoped only -- callers must not persist it.
    """
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except requests.RequestException:
        return None

    extractor = _TextExtractor()
    try:
        extractor.feed(response.text)
    except Exception:
        return None

    text = extractor.get_text()
    if not text:
        return None

    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "\n\n[truncated]"

    return text


def attach_source_text(
    documents: list[RetrievedDocument],
    max_documents_to_fetch: int = DEFAULT_MAX_DOCUMENTS_TO_FETCH,
    max_chars: int = DEFAULT_MAX_CHARS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[RetrievedDocument]:
    """Return documents with full_source_text populated where fetched.

    Only the top max_documents_to_fetch documents (by existing rank
    order) are fetched, in parallel, bounding both latency and how much
    third-party content one question pulls in. Documents beyond that
    limit, and any fetch that fails, keep full_source_text=None; the
    prompt builder falls back to the short indexed text for those.
    """
    to_fetch = documents[:max_documents_to_fetch]
    rest = documents[max_documents_to_fetch:]

    urls = [document.metadata.get("source_url") for document in to_fetch]

    with ThreadPoolExecutor(max_workers=max(1, len(urls))) as executor:
        fetched_texts = list(
            executor.map(
                lambda url: (
                    fetch_source_text(url, max_chars, timeout_seconds)
                    if url
                    else None
                ),
                urls,
            )
        )

    enriched = [
        replace(document, full_source_text=full_text)
        for document, full_text in zip(to_fetch, fetched_texts)
    ]

    return enriched + list(rest)
