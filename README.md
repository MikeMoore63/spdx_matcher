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

| Method         | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Aruments                                                                                                                                                                                                    | Returns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| normalize      | Provides means to take raw text and to make it usefule for matching or hashing purposes. Its main behavior is defined from [spdx matching specification](https://spdx.github.io/spdx-spec/v2.2.2/license-matching-guidelines-and-templates/). At the core it runs through all the basics of normalising i.e.<br/>* lowercse<br/>* change white spaces to single spaces<br/>* normalizes copyright<br/>* normalizes urls<br/>* applies varietal words from spx list<br/>* normalizes quotes to single quote<br/>* normalizes - or dashes<br/>* removes bullets/numbering <br/>In addition via flags you can optionally apply<br/><br/>spdx_matcher.LICENSE_HEADER_REMOVAL if set in remove_sections would remove LICENSE HEADER<br/><br/>spdx_matcher.COPYRIGHT_REMOVAL when this flag is set lines featuring word "copyright" are removed.<br/><br/>spdx_matcher.APPENDIX_ADDENDUM_REMOVAL any text with 'Appendix','Addendum','Exhibit' 'Appendum' is removed. <br/><br/>spdxmatcher.REMOVE_NONE normalises but does not remove any of sections previously.<br/><br/>spdx_matcher.REMOVE_FINGERPRINT = LICENSE_HEADER_REMOVAL &#124; COPYRIGHT_REMOVAL  this is intended to allow rapid hash matching of license texts as it just removes copyright which is unique to who produced license and license header. <br/><br/>To allow license comparison you may want to use these flags in various ways depending on context. Its also worth noting that for license matching none should be removed. The flags can be '&amp;' together to change behavior | license_text - The input text that requires normalizing.<br/> remove_sections - Default spdx_matcher.REMOVE_FINGERPRINT<br/>remove_sections controls the behavior of the normaliser based on what is in the | text normalised ready for comparison.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |   
| analyse_license_text | To parse input text and identify what if any license can be detected in text input.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | license_text = non normalised raw license text                                                                                                                                                              | matches- A dict object that contans scan results<br/>percent - this is a rough calculation of percentage of text that succesful extraction occured from. It is approximate as leading and trailing content exists in may lienses such as how to use the license etc. But this is intended to let you know if a large text if there was some idea of how much was not identified. As a common practice in 3rd party licenses is to bundle many licenses in one file. The ercentage is calculated by total-length - exemplar text length as provided by spdx for each match. Noteif alicense file repeates a license only the first match is ever returned. |

spdx_matcher is designed to work offline each release contains a cache updated from json from spdx source at https://github.com/spdx/license-list-data/tree/main/json the package includes the script that builds that cache build_spdx_matcher_cache used to build the cache. A copy of cache is bundled and used by default on each release.

You can override the cache with your locally built cache by setting environment variable SPDX_MATCHER_CACHE_FILE set this to alter where to write and read the cache.

Note building the cache also runs checking against sample texts to validate matchers work. Note the spdx data is not perfect as demonstrated when you build but its quite good.

This is currently in early release.

An example piece of code using the analyser below

```python
import os
import hashlib
import json
import re
import spdx_matcher
import time


import magic
from functools import lru_cache, cache
from google.cloud import storage,exceptions
import logging
import sys
import threading

if not logging.getLogger().hasHandlers():
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
logging.getLogger(__name__).setLevel(logging.INFO)

# a rough filter for files to process
LICENSE_RE = r'^.*LICENSE$|^.*LICENSE.*\.(?!(exe|dll|go|c|h|py|pyc|rb|sh|sql|jsonl)$)([^.]+$)'

# filter by mime type lets avoid binaries
def process_license(mime_type):
    """
    Determines if a files mime type should be processed or not
    Notably we avoid all executable files and shared libraries
    """
    retval = True if mime_type not in [
        "application/x-executable",
        "application/x-dosexec",
        "application/x-mach-binary",
        "application/x-sharedlib"] else False

    return retval

# process afile
def process_license_file(f, mime_type, match=False):
    # write licenses to a bucket for later analysis
    #
    global thread_local_original_content
    output = {}
    if not process_license(mime_type):
        return None,output
    try:
        # a simple normaliser of contents
        content_clean = []
        original_content = []
        
        # lets has text stuff in a way we can reduce spotting similar license
        if mime_type in ["text/plain","text/x-Algol68"]:
            original_content = f.read()
            content = spdx_matcher.normalize(original_content, spdx_matcher.REMOVE_FINGERPRINT)
        else:
            content = f.read()
            original_content = content

        if not isinstance(content,bytes):
            content = content.encode("utf-8")
        file_hash = hashlib.sha1(content).hexdigest()

        # ok I know odd but avoids putting content in the hash of the lru cache
        thread_local_original_content.content = original_content

        _, output = _store_content(file_hash, "License", mime_type, match)
    except (FileNotFoundError, UnicodeDecodeError) as e:
        return None, output

    return file_hash, output


thread_local_storage_client = threading.local()
thread_local_storage_bucket = threading.local()
storage_blob_lock = threading.Lock()
popular_object_cache = None
# we pass content by thread variable not parameter
# we do this as lru cache kesy on content content can vary we normalise
# to match keys so to avoid the keys differingwe pass by a thread variable
# the original content minus copyright. We do this to keep content as
# natral as possible within license analysis stack
thread_local_original_content = threading.local()


# effeciecient store content by using an lru cache for avoiding writing dupe license exemplars
# in this example using google cloud storage pick your favourite persistence
# approach
@lru_cache(maxsize=1000)
def _store_content(blob_name, ecosystem, mime_type, match=False):
    global thread_local_storage_client, thread_local_storage_bucket, popular_object_cache, \
        storage_blob_lock, thread_local_original_content
    blob_path_name = f"{ecosystem}/{blob_name}"
    output = {
        "licenses": {},
        "exceptions": {}
    }
    if "LICENSE_CFG_BUCKET" not in os.environ:
        return blob_name, output


    sc = getattr(
        thread_local_storage_client, 'sc', None)
    bucket = getattr(
        thread_local_storage_bucket, 'bucket', None)
    if sc is None:
        sc = storage.client.Client()
        thread_local_storage_client.sc = sc
        bucket = sc.bucket(os.environ["LICENSE_CFG_BUCKET"])
        thread_local_storage_bucket.bucket = bucket

    blob_content = thread_local_original_content.content
    if match:
        output,_ = spdx_matcher.analyse_license_text(blob_content)

    # allow popular licenses to be locally cached just a set of keys of hashes
    if popular_object_cache is None:
        with storage_blob_lock:
            if popular_object_cache is None:
                popular_object_cache = {}
                popular_license = storage.Blob(bucket=bucket, name="popular_objects.json")
                if popular_license.exists(sc):
                    popular_object_cache = json.loads(popular_object_cache.download_as_string())

    # we know we have popular cached already avoid rest overhead
    if blob_name in popular_object_cache:
        return blob_name, output

    # we attempt to create blob if we get it exists we skip as exists our job is done
    # we are hashing licenses and many scanners could be writing same license
    # analysis on sample show of 14k licenses only about 900 uniques existed
    # why we are going with the 1000 lru cache
    try:
        blob = storage.Blob(bucket=bucket, name=blob_path_name)
        if blob.exists(sc):
            logging.getLogger(__name__).debug(f"Checked object exists {blob_path_name}")
            return blob_name, output
        # 7 days thisstuff is not intended to change
        # so provide hints to cloud storage to maximise this
        blob.cache_control = "max-age=604800"
        blob.upload_from_string(blob_content, content_type=mime_type)
        logging.getLogger(__name__).info(f"Stored object {blob_path_name}")
    except exceptions.GoogleCloudError:
        logging.getLogger(__name__).exception(f"Unable to store object {blob_path_name}")
    return blob_name, output

# gen_license_input("spdxLic.jsonl", "spdxLicExceptions.jsonl", "spdxCache.json")
files_processed = 0
license_files_processed = 0
licenses_found = {"unknown": 0}
startTime = time.time()
license_processing = 0.0
for root, dirs, files in os.walk('.'):
    for file in files:
        if files_processed and files_processed % 5000 == 0:
            endTime = time.time()
            print(f"Processed {files_processed} {files_processed/(endTime - startTime - license_files_processed)}, licenses_processed {license_files_processed} {license_files_processed/license_processing} licenses_found {licenses_found}")
        files_processed += 1
        if re.match(LICENSE_RE,file, flags=re.IGNORECASE):
            license_files_processed += 1
            startLicenseTime = time.time()
            try:
                with open(os.path.join(root, file), errors="backslashreplace") as f:
                    magic_result = magic.from_buffer(f.read(2048),mime=True)
                with open(os.path.join(root, file)) as f:
                    hash, analysis = process_license_file(f, magic_result, match=True)
                if analysis:
                    if "licenses" in analysis and len(analysis['licenses']) == 0:
                        licenses_found["unknown"] += 1
                    for k in analysis['licenses']:
                        if k in licenses_found:
                            licenses_found[k] += 1
                        else:
                            licenses_found[k] = 1

            except (FileNotFoundError,UnicodeDecodeError) as e:
                continue
            finally:
                endLicenseTime = time.time()
                license_processing += (endLicenseTime - startLicenseTime)

endTime = time.time()
print(f"Processed {files_processed} {files_processed/(endTime - startTime - license_files_processed)}, licenses_processed {license_files_processed} {license_files_processed/license_processing} licenses_found {licenses_found}")
print(f"{_store_content.cache_info()}")
```

This package does contain data from SPDX which is release under the [Creative Commons Attribution 3.0](https://spdx.org/licenses/CC-BY-3.0] Unported) or CC-BY-3.0 license.





 