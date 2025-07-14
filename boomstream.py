#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import requests
import subprocess
import sys

from base64 import b64decode
from pathlib import Path
from typing import Any


DEBUG: bool = bool(os.getenv('BOOMSTREAM_DEBUG', False))
MAX_RETRIES: int = 5
XOR_KEY: str = 'bla_bla_bla'


def setup_logging(verbose: bool = False) -> logging.Logger:
    log_level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger()
    logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    return logger


class Downloader:
    def __init__(self, boomstream_config_file: str) -> None:
        """Initialize a new Downloader instance.

        Args:
            boomstream_config_file (str): The name of file containing `window.boomstreamConfig={...}` definition
        """
        self.logger = logging.getLogger(__name__)
        self.boomstream_config = boomstream_config_file
        self.config = self._load_boomstream_config(boomstream_config_file)

        self.headers = {
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ru',
            'authority': 'play.boomstream.com',
            'origin': self.referer,
            'path': '/sfQngWtf/config?version=1.2.84',
            'referer': self.referer,
        }

    @property
    def mediaData(self) -> Any:
        return self.config['mediaData']

    @property
    def posters_presented(self) -> bool:
        return bool(self.mediaData.get('posters') and len(self.mediaData['posters']) > 0)

    @property
    def records_presented(self) -> bool:
        return 'records' in self.mediaData

    @property
    def referer(self) -> str:
        return self.config['referrer']

    @property
    def title(self) -> str:
        return self.config['entity']['title']

    def __str__(self) -> str:
        info = {'File': self.boomstream_config, 'Title': self.title, 'Referer': self.referer}
        return str(info)

    __repr__ = __str__

    def _load_boomstream_config(self, config_file: str) -> dict:
        """Load and parse the boomstream config file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as file:
                file_content = file.read()

            pattern = r'window\.boomstreamConfig\s*=\s*(\{.*?\});'
            match = re.search(pattern, file_content, re.DOTALL)

            if match:
                config = json.loads(match.group(1))
            else:
                config = json.loads(file_content)

            _ = config['mediaData']
            return config

        except FileNotFoundError:
            sys.exit(f'File not found: {config_file}')
        except json.JSONDecodeError as e:
            sys.exit(f'JSON parsing error: {e}')
        except KeyError as e:
            sys.exit(f'Missing required key in config: {e}')

    def _extract_meta(self) -> None:
        """Extract token and m3u8_url from config."""
        if self.records_presented and self.posters_presented:
            source = self.mediaData['posters'][4]
        else:
            source = self.mediaData

        self.token = b64decode(source['token']).decode('utf-8')
        self.m3u8_url = b64decode(source['links']['hls']).decode('utf-8')

    def _check_live_translation(self) -> bool:
        """Check if video is available for download."""
        if not self.posters_presented:
            self.logger.error(
                'Video record is not available. '
                'Probably, the live streaming has not finished yet. '
                'Please, try to download once the translation is finished. '
                "If you're sure that translation is finished, please create an issue "
                'in project github tracker and attach your boomstream.config.json file'
            )
            return False
        return True

    def run(self) -> bool:
        self.logger.info(f'Title: {self.title}')
        self.logger.debug(self)

        if not self._check_live_translation():
            return False

        self._extract_meta()

        chunklist = self._get_chunklist()
        iv, key = self._get_aes_key(chunklist)

        if self._download_chunks(chunklist, iv, key):
            return self._merge_chunks(key)

        return False

    def _res2int(self, resolution) -> int:
        """Convert resolution string to integer value for comparison."""
        if 'x' in resolution:
            width, height = resolution.split('x', 1)
            return int(width) * int(height)
        else:
            return int(resolution)

    def _extract_chunklist_urls(self, playlist) -> list[Any]:
        result = []
        lines = playlist.split('\n')

        # Precompile regex patterns
        resolution_pattern = re.compile(r'RESOLUTION=(\d+x\d+)')
        bandwidth_pattern = re.compile(r'BANDWIDTH=(\d+)')

        i = 0
        while i < len(lines) - 1:  # Check pairs of lines
            line = lines[i]

            if line.startswith('#EXT-X-STREAM-INF'):
                # Get resolution or bandwidth
                resolution_match = resolution_pattern.search(line)
                if resolution_match:
                    resolution = resolution_match.group(1)
                else:
                    bandwidth_match = bandwidth_pattern.search(line)
                    if bandwidth_match:
                        resolution = bandwidth_match.group(1)
                    else:
                        i += 1
                        continue  # Skip if no resolution/bandwidth found

                # Get URL from next line
                url_line = lines[i + 1]
                if not url_line.startswith('#'):  # Make sure it's not another directive
                    result.append([resolution, url_line, self._res2int(resolution)])
                    i += 1  # Skip the URL line in next iteration

            i += 1

        if not result:
            raise ValueError('No valid streams found in playlist')

        return result

    def _get_chunklist(self) -> str:
        playlist = requests.get(self.m3u8_url, headers=self.headers).text

        all_chunklists = self._extract_chunklist_urls(playlist)
        self.logger.debug(
            f'This video is available in the following resolutions: {", ".join(i[0] for i in all_chunklists)}'
        )
        self.logger.info(f'Resolution: {max(all_chunklists, key=lambda x: x[2])[0]}')

        url = max(all_chunklists, key=lambda x: x[2])[1]
        self.logger.debug(f'URL: {url}')

        if not url:
            raise ValueError('Empty chunklist URL found')

        return requests.get(url, headers=self.headers).text

    def _decrypt(self, src_text, key) -> str:
        key_len_needed = (len(src_text) + 1) // 2
        key_e = (key * (key_len_needed // len(key) + 1))[:key_len_needed]

        return ''.join(chr(int(src_text[n : n + 2], 16) ^ ord(key_e[n // 2])) for n in range(0, len(src_text), 2))

    def _encrypt(self, src_text, key) -> str:
        key_e = key * (len(src_text) // len(key) + 1)
        key_e = key_e[: len(src_text)]

        return ''.join(f'{ord(s) ^ ord(k):02x}' for s, k in zip(src_text, key_e))

    def _get_aes_key(self, chunklist) -> tuple[str, str]:
        """Returns IV and 16-byte key which will be used to decrypt video chunks."""

        try:
            # X-MEDIA-READY contains a value used to calculate IV for AES-128 and a URL to obtain AES-128 encryption key.
            xmedia_ready = next(
                line.split(':', 1)[1].strip()
                for line in chunklist.split('\n')
                if line.startswith('#EXT-X-MEDIA-READY:')
            )
        except StopIteration:
            raise ValueError("Could not find '#EXT-X-MEDIA-READY:' in chunklist")

        self.logger.debug(f'X-MEDIA-READY: {xmedia_ready}')

        decr = self._decrypt(xmedia_ready, XOR_KEY)
        self.logger.debug(f'Decrypted X-MEDIA-READY: {decr}')

        prefix = decr[0:20]
        iv_bytes = decr[20:36]
        iv = ''.join(f'{ord(c):02x}' for c in iv_bytes)

        encrypted_data = self._encrypt(prefix + self.token, XOR_KEY)
        key_url = f'https://play.boomstream.com/api/process/{encrypted_data}'

        self.logger.debug(f'key url = {key_url}')
        key = requests.get(key_url, headers=self.headers).text

        self.logger.debug(f'IV = {iv}')
        self.logger.debug(f'Key = {key}')

        return iv, key

    def _download_chunks(self, chunklist, iv, key) -> bool:
        """Download all chunks into one directory."""
        tmp_dir = Path('tmp')
        tmp_dir.mkdir(exist_ok=True)

        key_dir = Path('tmp', key)

        key_dir.mkdir(exist_ok=True)

        hex_key = ''.join(f'{ord(c):02x}' for c in key)

        urls = [line for line in chunklist.split('\n') if line.startswith('https://')]

        chunks = len(urls)
        self.logger.info(f'Chunks to download: {chunks}')

        for i, url in enumerate(urls):
            outf = key_dir / f'{i:05d}.ts'

            if outf.exists():
                self.logger.debug(f'Chunk #{i} exists [{outf}]')
                continue

            sys.stdout.write(f'\rDownloading chunk {i}/{chunks}')
            sys.stdout.flush()

            for attempt in range(1, MAX_RETRIES):
                result = subprocess.run(
                    f'curl -s "{url}" | openssl aes-128-cbc -K "{hex_key}" -iv "{iv}" -d > "{outf}"',
                    shell=True,
                    check=False,
                )
                if result.returncode == 0:
                    break
                else:
                    self.logger.warning(f'curl return code: {result.returncode}. attempts: {attempt}/{MAX_RETRIES}')

                if attempt == MAX_RETRIES:
                    self.logger.error(f'Failed to download URL: {url} in {MAX_RETRIES} attempt. Skipped.')
                    return False

        sys.stdout.write(f'\r{" " * 60}\r')
        sys.stdout.flush()
        self.logger.info('All chunks successfully downloaded.')
        return True

    def _merge_chunks(self, key) -> bool:
        """Merges all chunks into one file and encodes it to MP4."""
        self.logger.info('Merging chunks...')

        subprocess.run(f'cat tmp/{key}/*.ts', shell=True, stdout=open(self._get_title(key), 'w'))
        self.logger.info(f'Result: {self._get_title(key)}')

        subprocess.run(f'rm tmp/{key}/*.ts', shell=True)
        os.rmdir(f'tmp/{key}')

        return True

    def _get_title(self, key) -> str:
        _, config_file = os.path.split(self.boomstream_config)
        config_file, _ = os.path.splitext(config_file)

        base, ext = os.path.splitext(self.title)
        ext = ext if ext else '.mp4'

        return f'{base} ({config_file})[{key}]{ext}'


def process_file(file: str) -> bool:
    return Downloader(file).run()


def process_directory(dir_path: str) -> None:
    logger = logging.getLogger(__name__)
    if not os.path.exists(dir_path):
        sys.exit(f"Error: Directory '{dir_path}' does not exist")

    if not os.path.isdir(dir_path):
        sys.exit(f"Error: '{dir_path}' is not a directory")

    files = []
    skipped_files = []
    skipped_dirs = []

    for file in os.listdir(dir_path):
        if os.path.isfile(Path(dir_path, file)):
            name, ext = os.path.splitext(file)
            if name[0] != '.' and not ext:
                files.append(file)
            else:
                skipped_files.append(file)
        else:
            skipped_dirs.append(file)

    logger.info(f"Found {len(files)} unprocessed files in '{dir_path}'")
    logger.debug(f"Skipped {len(skipped_files)} files in '{dir_path}': {skipped_files}")
    logger.debug(f"Skipped {len(skipped_dirs)} dirs in '{dir_path}': {skipped_dirs}")

    if files:
        logger.info(f'Files to procced: {files}')
        logger.info('-' * 50)

    for file_name in sorted(files):
        file_path = os.path.join(dir_path, file_name)
        logger.info(f'Processing file `{file_path}`.')
        file_processed = process_file(file_path)
        if file_processed:
            os.rename(file_path, f'{file_path}.done')
            logger.info(f'File `{file_path}` processed successfully.')
        else:
            logger.warning(f'File `{file_path}` not processed.')


def main() -> None:
    logger = setup_logging(verbose=DEBUG)  # Get the configured logger
    logger.info('Starting boomstream downloader')
    parser = argparse.ArgumentParser(description='Process files by reading and renaming them.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dir', help='Directory to process. Only files without extensions will be processed!')
    group.add_argument('--file', help='Single file to process (should contain boomstreamConfig JSON)')
    group.add_argument('filename', nargs='?', help='alternative syntax to process single file')

    args = parser.parse_args()

    if args.dir:
        process_directory(args.dir)
    else:
        file_path = args.file if args.file else args.filename
        process_file(file_path)


if __name__ == '__main__':
    main()
