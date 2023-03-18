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

LICENSE_RE = r'^.*LICENSE$|^.*LICENSE.*\.(?!(exe|dll|go|c|h|py|pyc|rb|sh|sql|jsonl)$)([^.]+$)'

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


def process_license_file(f, mime_type, match=False):
    # write licenses to a bucket for later analysis
    #
    global thread_local_original_content
    output = {}
    if not process_license(mime_type):
        return None,output
    try:
        # use spdx_matchers normalization algorithm that meets the spdx spec
        content_clean = []
        original_content = []
        if mime_type in ["text/plain","text/x-Algol68"]:
            original_content = f.read()
            if isinstance(original_content,bytes):
                original_content = f.read().decode("utf-8",errors='backslashreplace')
            content = spdx_matcher.normalize(original_content, spdx_matcher.REMOVE_FINGERPRINT)
        else:
            content = f.read()
            original_content = content

        if not isinstance(content,bytes):
            content = content.encode("utf-8")
        file_hash = hashlib.sha1(content).hexdigest()

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


@lru_cache(maxsize=1000)
def _store_content(blob_name, ecosystem, mime_type, match=False):
    global thread_local_storage_client, thread_local_storage_bucket, popular_object_cache, \
        storage_blob_lock, thread_local_original_content
    blob_path_name = f"{ecosystem}/{blob_name}"
    output = {
        "licenses": {},
        "exceptions": {}
    }
    blob_content = thread_local_original_content.content
    if match:
        output,_ = spdx_matcher.analyse_license_text(blob_content)

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
            print(f"Processed {files_processed} {files_processed/(endTime - startTime - license_processing)}, licenses_processed {license_files_processed} {license_files_processed/license_processing} licenses_found {licenses_found}")
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
print(f"Processed {files_processed} {files_processed/(endTime - startTime - license_processing)}, licenses_processed {license_files_processed} {license_files_processed/license_processing} licenses_found {licenses_found}")
print(f"{_store_content.cache_info()}")
