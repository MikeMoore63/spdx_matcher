The spdx_matcher module is a tool to help detect licenses from text files.

Simple use is

```python
import spdx_matcher

with open("LICENSE.txt") as myf:
    license_text = f.read()

licenses_detected, percent = spdx_matcher.analyse_license_text(license_text)

```

The license returned from operator is a simple dictionary of form;

```json
{
  "license": {
    "<spdx license id>": {
      "string":"value"
      ....
    }
  },
  "exceptions": {
    "<spdx exception id>": {
      "string":"value"
      ....
    }
  },
}
```

Where data is the named attributes in the [spdx template license specification](https://spdx.github.io/spdx-spec/v2.2.2/license-matching-guidelines-and-templates/) for sections named "var" and uses the names as defined in the template.

The matcher object has a number of other useful functions;

| Method         | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Aruments                                                                                                                                                                                                    | Returns                                              |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| normalize      | Provides means to take raw text and to make it usefule for matching or hashing purposes. Its main behavior is defined from [spdx matching specification](https://spdx.github.io/spdx-spec/v2.2.2/license-matching-guidelines-and-templates/). At the core it runs through all the basics of normalising i.e.<br/>* lowercse<br/>* change white spaces to single spaces<br/>* normalizes copyright<br/>* normalizes urls<br/>* applies varietal words from spx list<br/>* normalizes quotes to single quote<br/>* normalizes - or dashes<br/>* removes bullets/numbering <br/>In addition via flags you can optionally apply<br/><br/>spdx_matcher.LICENSE_HEADER_REMOVAL if set in remove_sections would remove LICENSE HEADER<br/><br/>spdx_matcher.COPYRIGHT_REMOVAL when this flag is set lines featuring word "copyright" are removed.<br/><br/>spdx_matcher.APPENDIX_ADDENDUM_REMOVAL any text with 'Appendix','Addendum','Exhibit' 'Appendum' is removed. <br/><br/>spdxmatcher.REMOVE_NONE normalises but does not remove any of sections previously.<br/><br/>spdx_matcher.REMOVE_FINGERPRINT = LICENSE_HEADER_REMOVAL &#124; COPYRIGHT_REMOVAL  this is intended to allow rapid hash matching of license texts as it just removes copyright which is unique to who produced license and license header. <br/><br/>To allow license comparison you may want to use these flags in various ways depending on context. Its also worth noting that for license matching none should be removed. The flags can be '&amp;' together to change behavior | license_text - The input text that requires normalizing.<br/> remove_sections - Default spdx_matcher.REMOVE_FINGERPRINT<br/>remove_sections controls the behavior of the normaliser based on what is in the | text normalised ready for comparison.                |   
| analyse_license_text | To parse input text and identify what if any license can be detected in text input.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | license_text = non normalised raw license text                                                                                                                                                              | spdx.LicenseMatch - object that contans scan results |

spdx_matcher is designed to work offline each release contains a cache updated from json from spdx source at https://github.com/spdx/license-list-data/tree/main/json the package includes the script that builds that cache spdx_matcher_cachebuilder used to build the cache. A copy of cache is bundled and used by default on each release.

You can override the cache with your locally built cache by setting environment variable SPDX_MATCHER_CACHE_FILE set this to alter where to write and read the cache.

Note building the cache also runs checking against sample texts to validate matchers work. Note the spdx data is not perfect as demonstrated when you build but its quite good.

This is currently in early release.




 