#!/usr/bin/env python
# -*- coding: utf-8 -*-
import copy
import unittest
import logging
import hashlib
import spdx_matcher
from pathlib import Path

from spdx_matcher.data_models import HeaderMatcher, TextMatcher

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
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

"""
You may think the test here are quite "light" and in general I would agree.
But I would highlight this module is heavily data driven. It lives and breathes by quality
of license templates available from spdx. The matching algorithm itself is generic.

The cache builder tests every template regexp generated against the exemplar license provided
also by SPDX. So you canuse that as more complete coverage of the templates. This though also does
test the algorithm quite heavily for the core algorithm. So I am relying on this above
what is here.

Hence main test quite simple but we do test a simple license file and complex large multi-license
file.

The second CHALLENGING.txt is meant to be about worst case of license file in the wild. This
helps identify
issues with regexp performance such as back tracking
"""

current_dir = Path(__file__).parent

with open(f"{current_dir}/APACHE.txt", mode="rt", encoding="utf-8") as af:
    APACHE2 = af.read()

with open(f"{current_dir}/PYTHON-2.0.1.txt", mode="rt", encoding="utf-8") as af:
    PYTHON201 = af.read()

with open(f"{current_dir}/GPL-3.0.txt", mode="rt", encoding="utf-8") as af:
    GPL30 = af.read()

with open(f"{current_dir}/MPL-2.0.txt", mode="rt", encoding="utf-8") as af:
    MPL20 = af.read()

with open(f"{current_dir}/CHALLENGING.txt", mode="rt", encoding="utf-8") as af:
    CHALLENGING = af.read()

with open(f"{current_dir}/NO-MATCH.txt", mode="rt", encoding="utf-8") as af:
    NOMATCH = af.read()

with open(f"{current_dir}/APACHE-HEADER.txt", mode="rt", encoding="utf-8") as af:
    APACHE_HEADER = af.read()

with open(f"{current_dir}/GPL-3.0-Interface-Exception.txt", mode="rt", encoding="utf-8") as af:
    GPL30_EXCEPTION = af.read()


class TestSimple(unittest.TestCase):
    def test_apache2(self):
        logger.debug("Starting normalize of apache2..")
        content = spdx_matcher.normalize(APACHE2,
                                         remove_sections=spdx_matcher.REMOVE_FINGERPRINT)
        logger.debug("Finished normalize of apache2..")
        if not isinstance(content, bytes):
            content = content.encode("utf-8")

        file_hash = hashlib.sha1(content).hexdigest()
        self.assertEqual("9c1a36810f95032b176e2b488f781b823a7cb63f", file_hash)
        analysis, match = spdx_matcher.analyse_license_text(APACHE2)

        self.assertEqual(len(analysis["licenses"]), 1)
        self.assertTrue("Apache-2.0" in analysis["licenses"])

    def test_mpl20(self):
        # cache data matchConfidence equal to 1.0
        index, match_cache = spdx_matcher._load_license_analyser_cache()
        self.assertTrue(match_cache["licenses"]["MPL-2.0"]["text"]["matchConfidence"] == 1.0)
        self.assertTrue(match_cache["licenses"]["MPL-2.0-no-copyleft-exception"]["text"]["matchConfidence"] == 1.0)

        analysis, match = spdx_matcher.analyse_license_text(MPL20)
        self.assertEqual(len(analysis["licenses"]), 1)
        # it may match both MPL-2.0 or MPL-2.0-no-copyleft-exception, so check with `startswith` syntax
        self.assertTrue(all(key.startswith("MPL-2.0") for key in analysis["licenses"].keys()))

    def test_post_match_python201(self):
        logger.debug("Starting analyse of python 2.0.1..")
        analysis, match = spdx_matcher.analyse_license_text(PYTHON201)
        self.assertEqual(len(analysis["licenses"]), 1)
        self.assertEqual(len(analysis["exceptions"]), 0)
        self.assertTrue("Python-2.0.1" in analysis["licenses"])

    def test_no_match(self):
        logger.debug("Starting analyse of not match license text..")
        analysis, match = spdx_matcher.analyse_license_text(NOMATCH)
        self.assertEqual(len(analysis["licenses"]), 0)
        self.assertEqual(len(analysis["exceptions"]), 0)

    def test_exception_match(self):
        logger.debug("Starting analyse of exception match..")
        analysis, match = spdx_matcher.analyse_license_text(GPL30_EXCEPTION)
        self.assertEqual(len(analysis["licenses"]), 0)
        self.assertEqual(len(analysis["exceptions"]), 1)
        self.assertTrue("GPL-3.0-interface-exception" in analysis["exceptions"])

    def test_header_match(self):
        logger.debug("Starting analyse of header match...")
        analysis, match = spdx_matcher.analyse_license_text(APACHE_HEADER, include_header_match=False)
        self.assertEqual(len(analysis["licenses"]), 0)
        self.assertEqual(len(analysis["exceptions"]), 0)
        analysis, match = spdx_matcher.analyse_license_text(APACHE_HEADER)
        self.assertEqual(len(analysis["licenses"]), 1)
        self.assertEqual(len(analysis["exceptions"]), 0)
        self.assertTrue("Apache-2.0" in analysis["licenses"])

    def test_backtracking_challenging(self):
        logger.debug("Starting normalize of challenging..")
        content = spdx_matcher.normalize(CHALLENGING,
                                         remove_sections=spdx_matcher.REMOVE_FINGERPRINT)
        logger.debug("Finished normalize of challenging..")
        if not isinstance(content, bytes):
            content = content.encode("utf-8")

        file_hash = hashlib.sha1(content).hexdigest()
        self.assertEqual("9980067309768dbcf990e9a2db73f6ecaedd907a", file_hash)

        analysis, match = spdx_matcher.analyse_license_text(CHALLENGING)

        self.assertEqual(len(analysis["licenses"]), 18)
        self.assertTrue("Apache-2.0" in analysis["licenses"])
        self.assertTrue("MIT" in analysis["licenses"])
        self.assertTrue("BSD-3-Clause" in analysis["licenses"])
        self.assertTrue("GPL-3.0-only" in analysis["licenses"])
        self.assertTrue("GPL-3.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-2.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-2.0-only" in analysis["licenses"])
        self.assertTrue("GPL-1.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-1.0-only" in analysis["licenses"])
        self.assertTrue("MPL-2.0" in analysis["licenses"])

    def test_deprecated_licenses_not_exists(self):
        analysis, match = spdx_matcher.analyse_license_text(GPL30)
        self.assertEqual(len(analysis["licenses"]), 2)
        self.assertTrue("GPL-3.0" not in analysis["licenses"])
        self.assertTrue("GPL-3.0-only" in analysis["licenses"] and "GPL-3.0-or-later" in analysis["licenses"])

    def test_fuzzy_match_normal(self):
        # remove some text from the license text
        test_case = copy.deepcopy(APACHE2)
        test_case = test_case[:-300]

        analysis, match = spdx_matcher.analyse_license_text(test_case)
        self.assertEqual(len(analysis["licenses"]), 0)

        result = spdx_matcher.fuzzy_license_text(test_case, threshold=0.95)
        self.assertNotEqual(len(result), 0)
        self.assertTrue("Apache-2.0" in [match_license["id"] for match_license in result])

    def test_fuzzy_match_matchConfidence_lt_1(self):
        """Test fuzzy match for license data attribute matchConfidence less than 1 in cache data."""
        _, cache_data = spdx_matcher._load_license_analyser_cache()

        for match_config in (HeaderMatcher(), TextMatcher()):
            need = 5
            for license_id, data in cache_data["licenses"].items():
                if need == 0:
                    break
                if data[match_config.regexp_exists] and data[match_config.name]["matchConfidence"] < 1:
                    license_text = data["metadata"][match_config.text]
                    # exact match without any licenses, but fuzzy match get some of the licenses
                    analysis, _ = spdx_matcher.analyse_license_text(license_text)
                    self.assertTrue(len(analysis["licenses"]) == 0)

                    fuzzy_result = spdx_matcher.fuzzy_license_text(license_text, threshold=0.95)
                    self.assertTrue(len(fuzzy_result) > 0)
                    self.assertTrue(license_id in [match_license["id"] for match_license in fuzzy_result])
                    need -= 1

    def test_version(self):
        self.assertTrue(spdx_matcher.__version__ is not None)


class TestNormalize(unittest.TestCase):
    def test_space_remove(self):
        logger.debug("Starting normalize test for specific symbol removal..")
        source = "space remove for . new start"
        expected = "space remove for. new start"
        self.assertEqual(expected, spdx_matcher.normalize(source))

    def test_bullet_should_keep(self):
        """
        Not all bullet points should be removed, some license like MPL use bullet points as part of the
        license text regexp
        """
        # original test to make sure behavior not change
        source = "******\n\n 6. Disclaimer of Warranty\n\n* abc *"
        expected = "****** disclaimer of warranty abc *"
        self.assertEqual(expected, spdx_matcher.normalize(source))

        source = "******\n\n 6. Disclaimer of Warranty\n\n* ------ *"
        expected = "****** disclaimer of warranty * ------ *"
        self.assertEqual(expected, spdx_matcher.normalize(source))

        source = "******\n\n 6. Disclaimer of Warranty\n\n* ====== *"
        expected = "****** disclaimer of warranty * ====== *"
        self.assertEqual(expected, spdx_matcher.normalize(source))

        source = "*******\n*  *\n*  6. Disclaimer of Warranty  *\n*  ------  *"
        expected = "******* disclaimer of warranty * ------ *"
        self.assertEqual(expected, spdx_matcher.normalize(source))


if __name__ == "__main__":
    unittest.main()
