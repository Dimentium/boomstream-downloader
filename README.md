# Boomstream Video Downloader

A Python tool to download videos from boomstream.com streaming service.

Based on:
- https://github.com/cleeque/boomstream-downloader (original code)
- https://github.com/kuznetsovin/boomstream-downloader (latest fork)

## Features

- Downloads videos from boomstream.com with the highest available resolution
- Handles HLS AES-128 encrypted video chunks
- Supports both individual file and batch directory processing
- Automatically merges downloaded chunks into a single video file

## Encryption Algorithm

The service stores video chunks encrypted using HLS AES-128 algorithm. To decrypt them:
1. AES initialization vector is extracted from the first part of `#EXT-X-MEDIA-READY` variable in the m3u8 playlist using XOR decryption
2. The 128-bit key is retrieved via HTTP from a URL that starts with `https://play.boomstream.com/api/process/`

## Execution

### Installation using [uv/uvx](https://docs.astral.sh/uv/#tool-management) (recommended)

```bash
# One-time install:
uv tool install git+https://github.com/Dimentium/boomstream-downloader
```

### Without installation:

```bash
uvx --from git+https://github.com/Dimentium/boomstream-downloader bsdl
```

## Usage

```bash
# Process a single file
bsdl --file <path_to_boomstream_config_file>
# or simply
bsdl <path_to_boomstream_config_file>

# Process all files in a directory (only files without extensions)
bsdl --dir <directory_path>
```

### Getting the Config File

You need a file containing the boomstreamConfig. This can be:
- `boomstream.config.json` file
- Full HTML page from `https://play.boomstream.com/0fabQfiA?title=0`

To get the file from your browser:
1. Open Developer Console (Network tab)
2. Find the page request
3. Save the response:
   - Safari: "Save file"
   - Firefox: "Save Response As"
   - Chrome: "Save as"

## Requirements

* Python 3.6+
* curl
* openssl
* requests library

## Environment Variables

- `BOOMSTREAM_DEBUG`: Set to any value to enable debug logging

## Notes

- The script was tested on macOS 15.4
- Uses GNU/Linux `cat` tool to merge video pieces
- Successfully processed files are renamed with a `.done` extension when using batch mode
