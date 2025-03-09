from __future__ import annotations
from dataclasses import dataclass


@dataclass
class BaseMatcher:
    id: str
    name: str
    template: str
    text: str
    exception_template: str
    exception_text: str
    regexp_exists: str
    metadata: str | None = "metadata"


@dataclass
class TextMatcher(BaseMatcher):
    id: str | None = "TextMatcher"
    name: str | None = "text"
    template: str | None = "standardLicenseTemplate"
    text: str | None = "licenseText"
    exception_template: str | None = "licenseExceptionTemplate"
    exception_text: str | None = "licenseExceptionText"
    regexp_exists: str | None = "textRegexpExists"


@dataclass
class HeaderMatcher(BaseMatcher):
    id: str | None = "HeaderMatcher"
    name: str | None = "header"
    template: str | None = "standardLicenseHeaderTemplate"
    text: str | None = "standardLicenseHeader"
    exception_template: str | None = "licenseExceptionHeaderTemplate"
    exception_text: str | None = "licenseExceptionHeaderText"
    regexp_exists: str | None = "headerRegexpExists"


@dataclass
class MatchCost:
    text: float
    header: float
