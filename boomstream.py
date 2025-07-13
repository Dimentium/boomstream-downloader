#!/usr/bin/env python3

import os
import re
import sys
import json
import requests
from base64 import b64decode


XOR_KEY = 'bla_bla_bla'

headers = {
    'authority': 'play.boomstream.com',
    'path': '/sfQngWtf/config?version=1.2.84',
    'origin': 'https://otus.ru',
    'accept-encoding': 'gzip, deflate, br',
    'referer': 'https://otus.ru/',
    'accept-language': 'ru',
}


class App:
    def get_token(self):
        if 'records' in self.config['mediaData'] and len(self.config['mediaData']['posters']) > 0:
            return b64decode(self.config['mediaData']['posters'][4]['token']).decode('utf-8')
        else:
            return b64decode(self.config['mediaData']['token']).decode('utf-8')

    def get_m3u8_url(self):
        if 'records' in self.config['mediaData'] and len(self.config['mediaData']['posters']) > 0:
            return b64decode(self.config['mediaData']['posters'][4]['links']['hls']).decode('utf-8')
        else:
            return b64decode(self.config['mediaData']['links']['hls']).decode('utf-8')

    def get_boomstream_config(self):
        f = open('boomstream.config.json', 'r')
        result = json.loads(f.read())

        return result

    def get_playlist(self, url):
        return requests.get(url, headers=headers).text

    def res2int(self, resolution):
        if 'x' in resolution:
            return int(resolution.split('x')[0]) * int(resolution.split('x')[1])
        else:
            return int(resolution)

    def extract_chunklist_urls(self, playlist):
        result = []
        resolution = None

        for line in playlist.split('\n'):
            if line.startswith('#EXT-X-STREAM-INF'):
                m = re.search(r'RESOLUTION=(\d+x\d+)', line)
                if m is not None:
                    resolution = m.group(1)
                else:
                    m = re.search(r'BANDWIDTH=(\d+)', line)
                    if m is not None:
                        resolution = m.group(1)
                    else:
                        raise Exception('Could not get resolution from EXT-X-STREAM-INF')
            elif resolution is not None:
                result.append([resolution, line, self.res2int(resolution)])
                resolution = None

        return result

    def get_chunklist(self, playlist):
        all_chunklists = self.extract_chunklist_urls(playlist)
        print('This video is available in the following resolutions: %s' % ', '.join(i[0] for i in all_chunklists))

        url = sorted(all_chunklists, key=lambda x: x[2])[-1][1]

        print('URL: %s' % url)

        if url is None:
            raise Exception('Could not find chunklist in playlist data')
        return requests.get(url, headers=headers).text

    def get_xmedia_ready(self, chunklist):
        """
        X-MEDIA-READY contains a value that is used to calculate IV for AES-128 and a URL
        to obtain AES-128 encryption key.
        """
        for line in chunklist.split('\n'):
            if line.split(':')[0] == '#EXT-X-MEDIA-READY':
                return line.split(':')[1]

        raise Exception('Could not find X-MEDIA-READY')

    def decrypt(self, source_text, key):
        result = ''
        while len(key) < len(source_text):
            key += key

        for n in range(0, len(source_text), 2):
            c = int(source_text[n : n + 2], 16) ^ ord(key[(int(n / 2))])
            result = result + chr(c)

        return result

    def encrypt(self, source_text, key):
        result = ''

        while len(key) < len(source_text):
            key += key

        for i in range(0, len(source_text)):
            result += '%0.2x' % (ord(source_text[i]) ^ ord(key[i]))

        return result

    def get_aes_key(self, xmedia_ready):
        """
        Returns IV and 16-byte key which will be used to decrypt video chunks
        """
        decr = self.decrypt(xmedia_ready, XOR_KEY)
        print('Decrypted X-MEDIA-READY: %s' % decr)

        key = None
        iv = ''.join(['%0.2x' % ord(c) for c in decr[20:36]])

        key_url = 'https://play.boomstream.com/api/process/' + self.encrypt(decr[0:20] + self.token, XOR_KEY)

        print('key url = %s' % key_url)

        r = requests.get(key_url, headers=headers)
        key = r.text
        print('IV = %s' % iv)
        print('Key = %s' % key)
        return iv, key

    def download_chunks(self, chunklist, iv, key):
        i = 0

        if not os.path.exists(key):
            os.mkdir(key)

        # Convert the key to format suitable for openssl command-line tool
        hex_key = ''.join(['%0.2x' % ord(c) for c in key])

        for line in chunklist.split('\n'):
            if not line.startswith('https://'):
                continue
            outf = os.path.join(key, '%0.5d' % i) + '.ts'
            if os.path.exists(outf):
                i += 1
                print('Chunk #%s exists [%s]' % (i, outf))
                continue
            print('Downloading chunk #%s' % i)
            os.system('curl -s "%s" | openssl aes-128-cbc -K "%s" -iv "%s" -d > %s' % (line, hex_key, iv, outf))
            i += 1

    def merge_chunks(self, key):
        """
        Merges all chunks into one file and encodes it to MP4
        """
        print('Merging chunks...')
        os.system(
            'cat %s/*.ts > %s.ts'
            % (
                key,
                key,
            )
        )
        os.system(
            'mv %s.ts "%s".mp4'
            % (
                key,
                self.get_title(),
            )
        )

    def get_title(self):
        return self.config['entity']['title']

    def run(self):
        self.config = self.get_boomstream_config()
        if len(self.config['mediaData']['posters']) == 0:
            print(
                'Video record is not available. Probably, the live streaming'
                'has not finished yet. Please, try to download once the translation'
                'is finished.'
                "If you're sure that translation is finished, please create and issue"
                'in project github tracker and attach your boomstream.config.json file'
            )
            return 1

        self.token = self.get_token()
        self.m3u8_url = self.get_m3u8_url()

        print('Token = %s' % self.token)
        print('Playlist: %s' % self.m3u8_url)

        playlist = self.get_playlist(self.m3u8_url)
        chunklist = self.get_chunklist(playlist)

        xmedia_ready = self.get_xmedia_ready(chunklist)

        print('X-MEDIA-READY: %s' % xmedia_ready)
        iv, key = self.get_aes_key(xmedia_ready)
        self.download_chunks(chunklist, iv, key)
        self.merge_chunks(key)


if __name__ == '__main__':
    app = App()
    sys.exit(app.run())
