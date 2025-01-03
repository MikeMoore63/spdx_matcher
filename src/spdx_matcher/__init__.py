#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
  Copyright 2023 Mike Moore

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
import logging
from concurrent.futures import ThreadPoolExecutor, wait
from functools import cache, wraps
from textwrap import wrap
from importlib.metadata import version

__all__ = [
    "__version__",
    "normalize",
    "LICENSE_HEADER_REMOVAL",
    "COPYRIGHT_REMOVAL",
    "APPENDIX_ADDENDUM_REMOVAL",
    "REMOVE_ALL",
    "REMOVE_FINGERPRINT",
    "REMOVE_NONE",
    "analyse_license_text",
]

__version__ = version("spdx_matcher")
logger = logging.getLogger(__name__)

DEFAULT_CACHE_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "spdxCache.json"
)

DEFAULT_CACHE_THREAD_POOL_WORKERS = int(os.environ.get("SPDX_MATCHER_CACHE_THREAD_POOL_WORKERS", 10))

URL_REGEX = (
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
)
COPYRIGHT_NOTICE_REGEX = r"((?<=\n)|.*)Copyright.*(?=\n|$)|Copyright.*\\n"
COPYRIGHT_SYMBOLS = r"[©Ⓒⓒ]"
BULLETS_NUMBERING_REGEX = (
    r"\s(([0-9a-z]\.\s)+|(\([0-9a-z]\)\s)+|(\*\s)+)|(\s\([i]+\)\s)"
)
COMMENTS_REGEX = r"(\/\/|\/\*|#) +.*"
EXTRANEOUS_REGEX = r"(?is)\s*end of terms and conditions.*"
ADDENDIUM_EXHIBIT_REGEX = r"(?si)^(APPENDIX|APADDENDUM|EXHIBIT|ADDENDUM).*"
VARIETAL_WORDS_SPELLING = {
    "acknowledgment": "acknowledgement",
    "analogue": "analog",
    "analyse": "analyze",
    "artefact": "artifact",
    "authorisation": "authorization",
    "authorised": "authorized",
    "calibre": "caliber",
    "cancelled": "canceled",
    "capitalisations": "capitalizations",
    "catalogue": "catalog",
    "categorise": "categorize",
    "centre": "center",
    "emphasised": "emphasized",
    "favour": "favor",
    "favourite": "favorite",
    "fulfil": "fulfill",
    "fulfilment": "fulfillment",
    "initialise": "initialize",
    "judgment": "judgement",
    "labelling": "labeling",
    "labour": "labor",
    "licence": "license",
    "maximise": "maximize",
    "modelled": "modeled",
    "modelling": "modeling",
    "offence": "offense",
    "optimise": "optimize",
    "organisation": "organization",
    "organise": "organize",
    "practise": "practice",
    "programme": "program",
    "realise": "realize",
    "recognise": "recognize",
    "signalling": "signaling",
    "sub-license": "sublicense",
    "sub license": "sublicense",
    "utilisation": "utilization",
    "whilst": "while",
    "wilful": "wilfull",
    "non-commercial": "noncommercial",
    "per cent": "percent",
    "owner": "holder",
}

# Matcher pre- and post-configuration
MATCHER_POST_LICENSE_REMOVE = {
    "Python-2.0": ("0BSD", "HPND",),
    "Python-2.0.1": ("0BSD", "HPND",),
}

# a data structure to allow template overrides if match does not happen but its important
TEMPLATE_OVERRIDE = {}

LICENSE_HEADER_REMOVAL = 0x01
COPYRIGHT_REMOVAL = 0x02
APPENDIX_ADDENDUM_REMOVAL = 0x04
REMOVE_ALL = LICENSE_HEADER_REMOVAL | COPYRIGHT_REMOVAL | APPENDIX_ADDENDUM_REMOVAL
REMOVE_FINGERPRINT = LICENSE_HEADER_REMOVAL | COPYRIGHT_REMOVAL
REMOVE_NONE = 0x0
MAX_LINE_SIZE = 3 * 1024
LARGE_CONTENT = 30 * 1024


def normalize(license_text, remove_sections=REMOVE_FINGERPRINT):
    """Normalize the license text with all the SPDX license list matching guidelines.

    Arguments:
        license_text {string} -- license_text is the license text of the license.

    Returns:
        string -- license text nomalized with all the SPDX matching guidelines.
    """

    # remove very wide lines
    license_lines = license_text.split("\n")
    license_lines = [line for line in license_lines if len(line) < MAX_LINE_SIZE]
    license_text = "\n".join(license_lines)

    # To avoid a possibility of a non-match due to urls not being same.
    license_text = re.sub(
        URL_REGEX, "normalized/url", license_text, flags=re.IGNORECASE
    )

    # To avoid the license mismatch merely due to the existence or absence of code comment
    # indicators placed within the license text, they are just removed.
    license_text = re.sub(COMMENTS_REGEX, "", license_text, flags=re.IGNORECASE)

    # To avoid a license mismatch merely because extraneous text that appears at the end of the
    # terms of a license is different or missing.
    if remove_sections & APPENDIX_ADDENDUM_REMOVAL:
        license_text = re.sub(EXTRANEOUS_REGEX, "", license_text, flags=re.IGNORECASE)
        license_text = re.sub(
            ADDENDIUM_EXHIBIT_REGEX, "", license_text, flags=re.IGNORECASE
        )

    # By using a default copyright symbol (c)", we can avoid the possibility of a mismatch.
    # normalise copyright
    # B.10 Copyright symbol
    license_text = re.sub(COPYRIGHT_SYMBOLS, "(C)", license_text, flags=re.IGNORECASE)

    # To avoid a license mismatch merely because the copyright notice is different, it is not
    # substantive and is removed.
    # B.11 Copyright notice removal for matching
    if remove_sections & COPYRIGHT_REMOVAL:
        license_text = re.sub(
            COPYRIGHT_NOTICE_REGEX, r"\1", license_text, flags=re.IGNORECASE
        )

    # To avoid a possibility of a non-match due to case sensitivity.
    license_text = license_text.lower()

    # B.6.3 Guideline: hyphens, dashes
    license_text = license_text.replace("–", "-").replace("—", "-")

    # To remove the license name or title present at the beginning of the license text.
    if (
        remove_sections & LICENSE_HEADER_REMOVAL
        and "license" in license_text.split("\n")[0]
    ):
        license_text = "\n".join(license_text.split("\n")[1:])

    # B.6.4 Guideline: Quotes
    license_text = (
        license_text.replace('"', "'")
        .replace("`", "'")
        .replace("“", "'")
        .replace("”", "'")
        .replace("´", "'")
        .replace("‘", "'")
        .replace("’", "'")
    )

    # To avoid the possibility of a non-match due to variations of bullets, numbers, letter,
    # or no bullets used are simply removed.
    license_text = re.sub(BULLETS_NUMBERING_REGEX, " ", license_text)

    # To avoid the possibility of a non-match due to the same word being spelled differently.
    for initial, final in list(VARIETAL_WORDS_SPELLING.items()):
        license_text = license_text.replace(initial, final)

    # To avoid the possibility of a non-match due to different spacing of words, line breaks,
    # or paragraphs.
    license_text = re.sub(r" +", " ", " ".join(license_text.split()))

    # To avoid the possibility of a non-match due to missing space before or after specific symbol
    # including period, comma, question mark, exclamation mark, colon, semicolon.
    license_text = license_text.replace(" .", ".").replace(" ,", ",").replace(" !", "!")

    return license_text


def _fetch_json(url: str, timeout=10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _process_license(license: dict) -> dict:
    if "detailsUrl" in license:
        json_detail_data = _fetch_json(license["detailsUrl"])
        json_detail_data.pop("licenseTextHtml", None)
        json_detail_data.pop("standardLicenseHeaderHtml", None)
        if "standardLicenseTemplate" in json_detail_data:
            json_detail_data["regexpForMatch"] = _convert_template_to_regexp(
                json_detail_data["standardLicenseTemplate"]
            )

        if "licenseText" in json_detail_data:
            if "regexpForMatch" in json_detail_data:
                start_time = time.time()
                match, license_data, full_match = _license_regexps_match(
                    json_detail_data["regexpForMatch"],
                    json_detail_data["licenseText"],
                    fast_exit=False,
                )
                execution_time = time.time() - start_time
                json_detail_data["matchCost"] = execution_time
                json_detail_data["matchConfidence"] = match
                if match < 0.99 and license["licenseId"] in TEMPLATE_OVERRIDE:
                    print(
                        f"Unable to match {match} full_match:{full_match}  exmplar text "
                        f"to regexp for license {json_detail_data['licenseId']}  "
                        f"license_data {json.dumps(license_data)} time {execution_time} "
                        f"but we have override testing override"
                    )
                    json_detail_data[
                        "regexpForMatch"
                    ] = _convert_template_to_regexp(
                        TEMPLATE_OVERRIDE[license["licenseId"]]
                    )
                    start_time = time.time()
                    match, license_data, full_match = _license_regexps_match(
                        json_detail_data["regexpForMatch"],
                        json_detail_data["licenseText"],
                        fast_exit=False,
                    )
                    execution_time = time.time() - start_time
                    json_detail_data["matchCost"] = execution_time
                    json_detail_data["matchConfidence"] = match

                if match < 0.99:
                    print(
                        f"Unable to match {match} full_match:{full_match}  exmplar "
                        f"text to regexp for license {json_detail_data['licenseId']}  "
                        f"license_data {json.dumps(license_data)} time {execution_time}"
                    )
                else:
                    print(
                        f"Success to match and full_match:{full_match} exmplar text "
                        f"to regexp for license {json_detail_data['licenseId']} "
                        f"license_data {json.dumps(license_data)} time {execution_time}"
                    )

        for k in json_detail_data:
            if k not in license:
                license[k] = json_detail_data[k]
        return {
            license["licenseId"]: {
                "name": license["name"],
                "regexpForMatch": license["regexpForMatch"],
                "matchCost": license["matchCost"] if "matchCost" in license else 100.0,
                "text_length": len(license["licenseText"]),
                "matchConfidence": license["matchConfidence"],
                "isDeprecatedLicenseId": license["isDeprecatedLicenseId"],
            }
        }


def _process_exception(exception: dict) -> dict:
    if "detailsUrl" in exception:
        json_detail_data = _fetch_json(exception["detailsUrl"])
        if "licenseExceptionTemplate" in json_detail_data:
            json_detail_data["regexpForMatch"] = _convert_template_to_regexp(
                json_detail_data["licenseExceptionTemplate"]
            )
        if "licenseExceptionText" in json_detail_data:
            if "regexpForMatch" in json_detail_data:
                start_time = time.time()
                match, license_data, full_match = _license_regexps_match(
                    json_detail_data["regexpForMatch"],
                    json_detail_data["licenseExceptionText"],
                    fast_exit=False,
                )
                execution_time = time.time() - start_time
                json_detail_data["matchCost"] = execution_time
                json_detail_data["matchConfidence"] = match
                if match < 0.99:
                    print(
                        f"Unable to match {match} full_match:{full_match}  exmplar text "
                        f"to regexp for exception "
                        f"{json_detail_data['licenseExceptionId']}  "
                        f"license_data {json.dumps(license_data)} time {execution_time}"
                    )
                else:
                    print(
                        f"Success to match and full_match:{full_match} exmplar text to "
                        f"regexp for exception {json_detail_data['licenseExceptionId']} "
                        f"license_data {json.dumps(license_data)} time {execution_time}"
                    )
        for k in json_detail_data:
            if k not in exception:
                exception[k] = json_detail_data[k]
        return {
            exception["licenseExceptionId"]: {
                "name": exception["name"],
                "regexpForMatch": exception["regexpForMatch"],
                "matchCost": exception["matchCost"]
                if "matchCost" in exception
                else 100.0,
                "text_length": len(exception["licenseExceptionText"]),
                "matchConfidence": exception["matchConfidence"],
                "isDeprecatedLicenseId": exception["isDeprecatedLicenseId"],
            }
        }


def _merge_cache_data_match_cost(cache_file: str, match_cache: dict) -> None:
    """
    Merge attribute `matchCost` in cache data file to dict match_cache. to reduce the git diff.

    :param cache_file: The path of the cache file
    :param match_cache: The dict of match_cache
    """
    cache_data_match_cost = {"licenses": {}, "exceptions": {}}
    with open(cache_file, "r", encoding="utf-8") as cf:
        cache_data = json.load(cf)
        cache_data_match_cost["licenses"] = {
            license_id: license_data["matchCost"]
            for license_id, license_data in cache_data["licenses"].items()
        }
        cache_data_match_cost["exceptions"] = {
            license_exception_id: exception_data["matchCost"]
            for license_exception_id, exception_data in cache_data["exceptions"].items()
        }

    for license_id, license_data in match_cache["licenses"].items():
        if license_id in cache_data_match_cost["licenses"]:
            license_data["matchCost"] = cache_data_match_cost["licenses"][license_id]
    for license_exception_id, exception_data in match_cache["exceptions"].items():
        if license_exception_id in cache_data_match_cost["exceptions"]:
            exception_data["matchCost"] = cache_data_match_cost["exceptions"][license_exception_id]


def cache_builder(change_match_cost: bool | None = True) -> None:
    """
    Builds the cache file base on spdx licenses and exceptions json files

    :param change_match_cost: Whether change attribute `matchCost` in cache data file, use to reduce the diff
        of git commit, Will use the realtime match cost for current runtime if True, otherwise will use
        previous match cost in the cache data file. Default is True.
    """
    match_cache = {"licenses": {}, "exceptions": {}}
    base_url = "https://spdx.org/licenses"

    # Fetch licenses.json
    licenses_data = _fetch_json(f"{base_url}/licenses.json")
    exceptions_data = _fetch_json(f"{base_url}/exceptions.json")

    # Process licenses and exceptions using ThreadPoolExecutor
    licenses = []
    exceptions = []
    with ThreadPoolExecutor(max_workers=DEFAULT_CACHE_THREAD_POOL_WORKERS) as executor:
        # Process licenses concurrently
        for license in licenses_data["licenses"]:
            licenses.append(executor.submit(_process_license, license))

        # Process exceptions concurrently
        for exception in exceptions_data["exceptions"]:
            exceptions.append(executor.submit(_process_exception, exception))

    wait(licenses)
    wait(exceptions)
    for license in licenses:
        match_cache["licenses"].update(license.result())
    for exception in exceptions:
        match_cache["exceptions"].update(exception.result())

    cache_file = os.getenv("SPDX_MATCHER_CACHE_FILE", DEFAULT_CACHE_PATH)
    if not change_match_cost:
        logger.info("Not changing the match cost in the cache data file, due to parameter "
                    "`change_match_cost` is False")
        _merge_cache_data_match_cost(cache_file, match_cache)

    # Save match_cache to a file
    with open(cache_file, "w", encoding="utf-8") as cf:
        # Sort the licenses and exceptions by licenseId/licenseExceptionId for easier maintenance
        match_cache["licenses"] = dict(sorted(match_cache["licenses"].items()))
        match_cache["exceptions"] = dict(sorted(match_cache["exceptions"].items()))
        json.dump(match_cache, cf, indent=4)


def _convert_template_to_regexp(template):
    """
    Takes in an spdx template and returns an ordered array of regexp that can be used to match to
    a text file.
    Has 2 array 1 fingerprint is fixed text for high speed sanity check second is regexps to use
    once
    you have some certainty the licens emay be in the text
    """
    chunks = template.split(">>")
    regex_for_match = ""
    field_names = []
    regexp_to_match = []
    finger_prints = []
    regexp_in_total = 0
    regexp_open = 0
    avoid_greedy_regexp = False
    non_optional_text_done = 0

    for chunk_num, chunk in enumerate(chunks):
        sub_chunks = chunk.split("<<")
        for sub_chunk in sub_chunks:
            if sub_chunk.strip() == "":
                continue
            if (
                regexp_open == 0
                and len(regex_for_match) > 512
                and not avoid_greedy_regexp
                and non_optional_text_done > 0
            ):
                regexp_to_match.append(regex_for_match)
                non_optional_text_done = 0
                regex_for_match = ""
            if sub_chunk.startswith("beginOptional"):
                regexp_open += 1
                regexp_in_total += 1
                text = r"[ ]*(|"
            elif sub_chunk.startswith("endOptional"):
                regexp_open -= 1
                text = r")[ ]*"
            elif sub_chunk.startswith("var"):
                regexp_in_total += 1
                var_chunks = sub_chunk.split(";")
                real_chunks = []
                last_append = False
                for var_chunk_num, sub_var_chunk in enumerate(var_chunks):
                    temp_last_append = False
                    if sub_var_chunk.endswith("\\"):
                        temp_last_append = True
                        sub_var_chunk = sub_var_chunk[:-1]
                    else:
                        temp_last_append = False
                    if last_append:
                        real_chunks[len(real_chunks) - 1] = (
                            real_chunks[len(real_chunks) - 1] + sub_var_chunk
                        )
                    else:
                        real_chunks.append(sub_var_chunk)
                    last_append = temp_last_append
                rege_exp_to_use = None
                field_name = None
                for sub_var_chunk in real_chunks:
                    if sub_var_chunk.startswith("match="):
                        # remove quotes only at start and end not in the middle
                        rege_exp_to_use = re.sub(
                            r"^[\"'](.*)[\"']$", r"\1", sub_var_chunk[len("match=") :]
                        )
                        # replace white spaces with a single space in case has wierd text so will
                        # match original input text
                        # normalize words
                        # normalize copyright
                        # normalize quotes
                        # normalize white space
                        rege_exp_to_use = normalize(
                            rege_exp_to_use, remove_sections=REMOVE_NONE
                        )
                        # relax 0 to 20 to 0 to 40 as recognised as incorrectly done
                        rege_exp_to_use = rege_exp_to_use.replace(".{0,20}", ".{0,40}")
                        # make sure regexps are valid
                        try:
                            re.compile(rege_exp_to_use)
                        except re.error:
                            rege_exp_to_use = rf".{{0,{len(rege_exp_to_use)}}}"

                    if sub_var_chunk.startswith("name="):
                        field_name = (
                            sub_var_chunk[len("name=") :]
                            .replace('"', "")
                            .replace("'", "")
                        )
                        # remove invalid python variable name characters
                        # must start with alpha or underscore
                        if field_name[0].isdigit():
                            field_name[0] = "_"
                        field_name = re.sub(r"[^a-zA-Z0-9_]", "_", field_name)
                        if field_name in field_names:
                            field_name = None
                        else:
                            field_names.append(field_name)
                if field_name:
                    text = r"[ ]*" + rf"(?P<{field_name}>{rege_exp_to_use})" + r"[ ]*"
                else:
                    text = r"[ ]*" + rege_exp_to_use + r"[ ]*"
                avoid_greedy_regexp = True
            else:
                text = normalize(sub_chunk, remove_sections=REMOVE_NONE)
                if len(text) > 50 and regexp_open == 0:
                    finger_prints.append(text)
                text = re.escape(text)
                avoid_greedy_regexp = False
                # counts number of chunks of text outsid eof optional blocks
                # we do this to eliminate matches against a section of just many optionals
                if regexp_open == 0:
                    non_optional_text_done += 1
            regex_for_match = regex_for_match + text

    # close and open optionals
    for i in range(regexp_open):
        text = r")[ ]*"
        regex_for_match = regex_for_match + text

    regexp_to_match.append(regex_for_match)
    regexp_to_return = []
    for regexp_chunk in regexp_to_match:
        regexp_chunk = (
            regexp_chunk.replace("(|)", "")
            .replace("[ ]*[ ]*", "[ ]*")
            .replace(
                "[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*",
                "[ ]*",
            )
            .replace("[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}", "[ ]*")
            .replace("[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}", "[ ]*.*")
            .replace("[ ]*.{0,40}[ ]*.{0,40}[ ]*.{0,40}", "[ ]*.*")
            .replace("[ ]*.{0,40}[ ]*.{0,40}", "[ ]*.*")
            .replace("\\ ", " ")
        )
        regexp_to_return.append(regexp_chunk)

    return {"regexps": regexp_to_return, "finger_prints": finger_prints}


def _license_regexps_match(regexp_to_match_input, license, fast_exit=True):
    """
    Basic matcher given alist of regexp will iterate through them looking for
    contigous match f them in the license text using basic normalisation

    returns: match_certainty ->float, data ->dict, full_match->boolean
    match_certainty means - the regexp matched 100% in sequence if only a subset matched
    this is percentage that matched.
    data - a dictionary keyed by template field names (where valid in python) with content extracted
    full_match - at end of match we run full text normalization this drops top license
    strips copyright lines and removes addendum if text is nothing after this then this is true
    indicates maybe other text. If the license is 1 in a list this could lead to fals epositive.
    At least 2 matches should be attenpted. But this is to help with caller being able to decide if
    they want to retry with other matches.
    """
    normalized_all_license = normalize(license, remove_sections=REMOVE_NONE)
    initial_regexp = regexp_to_match_input["regexps"][0]
    max_match = 0
    max_data = {}

    start_find = 0
    fp_match = 0
    for fp_index, finger_print in enumerate(regexp_to_match_input["finger_prints"]):
        index = normalized_all_license.find(finger_print, start_find)
        if index >= 0:
            start_find = index + len(finger_print)
            fp_match += 1
        else:
            if fast_exit:
                return 0, max_data, 0

    num_regexp = len(regexp_to_match_input["regexps"])
    if num_regexp > 1:
        regexp_to_match = regexp_to_match_input["regexps"][1:]
    else:
        regexp_to_match = []

    # for fall through i.e. no matches at all
    normalized_license = normalized_all_license

    # we use findall on assumption a doc may have many licenses
    # it assumes that only one of each type
    # however we may have similar text in licenses so we iterate
    # success is finding it all
    for item_num, initial_match in enumerate(
        re.finditer(initial_regexp, normalized_all_license, flags=re.IGNORECASE)
    ):
        logging.getLogger(__name__).debug(f"iterating regexp {item_num}")
        normalized_license = normalized_all_license[initial_match.end() :]
        matches = 1
        non_matches = 0
        all_data = {}

        # we will also return names fields from template if any
        for key in initial_match.groupdict():
            all_data[key] = initial_match.groupdict()[key]

        # matches have to be sequential we assume input may include many licenses
        # that licenses may even have matching starts
        # so we validate all
        for regexp in regexp_to_match:
            # ok so if we had a mismatch at least check rest using search to see how much matches
            if non_matches > 0:
                match = re.search(regexp, normalized_license, flags=re.IGNORECASE)
            else:
                match = re.match(regexp, normalized_license, flags=re.IGNORECASE)
            if not match:
                non_matches += 1
                if fast_exit:
                    return matches / num_regexp, all_data, False
            else:
                for key in match.groupdict():
                    all_data[key] = match.groupdict()[key]
                matches += 1
                normalized_license = re.sub(regexp, "", normalized_license, count=1)

        # hey we found all of it contigously happy days
        if matches / num_regexp == 1.0:
            return (
                matches / num_regexp,
                all_data,
                len(normalize("\n".join(wrap(normalized_license)))) == 0,
            )

        max_match = (
            matches / num_regexp if matches / num_regexp > max_match else max_match
        )
        max_data = all_data if len(all_data) > len(max_data) else max_data

    return max_match, max_data, len(normalize("\n".join(wrap(normalized_license)))) == 0


@cache
def _load_license_analyser_cache():
    """
    Function that loads the cache
    :return:
    """
    cache_file = os.getenv("SPDX_MATCHER_CACHE_FILE", DEFAULT_CACHE_PATH)
    with open(cache_file, mode="rt", encoding="utf-8") as cf:
        match_cache = json.loads(cf.read())

    index = {"licenses": [], "exceptions": []}
    popular_license = [
        "Apache-2.0",
        "MIT",
        "LGPL-2.0-only",
        "Apache-1.0",
        "Apache-1.1",
        "BSD-3-Clause",
        "BSD-3-Clause-Attribution",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "GPL-2.0-or-later",
        "GPL-2.0-only",
        "GPL-1.0-or-later",
        "GPL-1.0-only",
        # dangerous?
        "AGPL-1.0-only",
        "AGPL-1.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    ]

    licenses_to_use = [
        {"id": k} | v
        for k, v in match_cache["licenses"].items()
        if v["matchConfidence"] == 1.0 and not v["isDeprecatedLicenseId"] and k not in popular_license
    ]
    license_to_use = [
        license["id"]
        for license in sorted(licenses_to_use, key=lambda x: x["matchCost"])
    ]
    popular_license.extend(license_to_use)
    index["licenses"] = popular_license
    exceptions_to_use = [
        {"id": k} | v
        for k, v in match_cache["exceptions"].items()
        if v["matchConfidence"] == 1.0 and not v["isDeprecatedLicenseId"]
    ]
    exceptions_to_use = [
        exception["id"]
        for exception in sorted(exceptions_to_use, key=lambda x: x["matchCost"])
    ]
    index["exceptions"] = exceptions_to_use

    return index, match_cache


def matcher_poster(func):
    """
    Decorator to post process the result from the matcher.

    We should add some additional process for the result, to avoid noise in the result. such as:
    - Remove some match licenses: License A is a subset of License B, we should remove License A
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        result, match = func(*args, **kwargs)
        if "licenses" not in result:
            return result, match

        rm_licenses = set()
        matcher_licenses = set(result["licenses"].keys())
        for match_license_id in matcher_licenses:
            if match_license_id in MATCHER_POST_LICENSE_REMOVE:
                rm_curr = set(MATCHER_POST_LICENSE_REMOVE[match_license_id])
                rm_licenses |= rm_curr & matcher_licenses

        if rm_licenses:
            logger.info("Remove match licenses: %s, according to config MATCHER_POST_LICENSE_REMOVE",
                        rm_licenses)
            for rm_license_id in rm_licenses:
                result["licenses"].pop(rm_license_id)
        return result, match

    return wrapper


@matcher_poster
def analyse_license_text(original_content, avoid_license=None, avoid_exceptions=None):
    """
    This method uses regexp cache to search for license text.
    It keeps looking until checks finished or sum o flicense text
    and exceptions are longer than the content.
    Starts with license then does exceptions.
    """
    index, match_cache = _load_license_analyser_cache()

    # expensive licenses
    # avoid if content considered large
    # regexp has back tracking which is inefficient
    if avoid_license is None:
        if len(original_content) > LARGE_CONTENT:
            avoid_license = [
                "0BSD",
                "JSON",
                "Zlib",
                "BSD-Source-Code",
                "BSD-2-Clause",
                "BSD-2-Clause-Views",
            ]
        else:
            avoid_license = []

    if avoid_exceptions is None:
        avoid_exceptions = []

    analysed_length = 0

    analysis = {"licenses": {}, "exceptions": {}}

    for lic_num, id in enumerate(index["licenses"]):
        if id in avoid_license:
            continue
        to_process = match_cache["licenses"][id]
        logging.getLogger(__name__).debug(f"processing license {id}")
        match, license_data, full_match = _license_regexps_match(
            to_process["regexpForMatch"], original_content, fast_exit=True
        )

        if match == 1.0:
            logging.getLogger(__name__).debug(f"matched license {id}")
            analysed_length += to_process["text_length"]
            analysis["licenses"][id] = license_data

        # if we have done whole text no exceptions
        if analysed_length >= len(original_content):
            return analysis, 1.0

    for lic_num, id in enumerate(index["exceptions"]):
        if id in avoid_exceptions:
            continue
        to_process = match_cache["exceptions"][id]
        logging.getLogger(__name__).debug(f"processing exceptions {id}")
        match, license_data, full_match = _license_regexps_match(
            to_process["regexpForMatch"], original_content, fast_exit=True
        )
        if match == 1.0:
            analysed_length += to_process["text_length"]
            analysis["exceptions"][id] = license_data

        # if done all text exit no point in testing further
        if analysed_length >= len(original_content):
            return analysis, 1.0

    return analysis, analysed_length / len(original_content)


# to help with local devugging of cache builder
if __name__ == "__main__":
    cache_builder(change_match_cost=True)
