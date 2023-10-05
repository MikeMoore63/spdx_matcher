#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import logging
import hashlib
import spdx_matcher

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

with open("tests/APACHE.txt", mode="rt", encoding="utf-8") as af:
    APACHE2 = af.read()

with open("tests/CHALLENGING.txt", mode="rt", encoding="utf-8") as af:
    CHALLENGING = af.read()


class TestSimple(unittest.TestCase):
    def test_apache2(self):
        logging.getLogger(__name__).debug("Starting normalize of apache2..")
        content = spdx_matcher.normalize(APACHE2,
                                         remove_sections=spdx_matcher.REMOVE_FINGERPRINT)
        logging.getLogger(__name__).debug("Finished normalize of apache2..")
        if not isinstance(content, bytes):
            content = content.encode("utf-8")

        file_hash = hashlib.sha1(content).hexdigest()
        self.assertEqual("fa8660bce4fd6ead891a22065375c2615fc6832c", file_hash)
        analysis, match = spdx_matcher.analyse_license_text(APACHE2)

        self.assertEqual(len(analysis["licenses"]), 1)
        self.assertTrue("Apache-2.0" in analysis["licenses"])

    def test_backtracking_challenging(self):
        logging.getLogger(__name__).debug("Starting normalize of challenging..")
        content = spdx_matcher.normalize(CHALLENGING,
                                         remove_sections=spdx_matcher.REMOVE_FINGERPRINT)
        logging.getLogger(__name__).debug("Finished normalize of challenging..")
        if not isinstance(content, bytes):
            content = content.encode("utf-8")

        file_hash = hashlib.sha1(content).hexdigest()
        self.assertEqual("ea09e167c20dc7c80252f9dd897bb903c14e7f89", file_hash)

        analysis, match = spdx_matcher.analyse_license_text(CHALLENGING)

        self.assertEqual(len(analysis["licenses"]), 16)
        self.assertTrue("Apache-2.0" in analysis["licenses"])
        self.assertTrue("MIT" in analysis["licenses"])
        self.assertTrue("BSD-3-Clause" in analysis["licenses"])
        self.assertTrue("GPL-3.0-only" in analysis["licenses"])
        self.assertTrue("GPL-3.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-2.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-2.0-only" in analysis["licenses"])
        self.assertTrue("GPL-1.0-or-later" in analysis["licenses"])
        self.assertTrue("GPL-1.0-only" in analysis["licenses"])


if __name__ == "__main__":
    unittest.main()
