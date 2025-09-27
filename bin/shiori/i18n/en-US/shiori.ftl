shiori-about = Yet another m3u8 downloader

download-wait = Wait for stream to start when no stream is detected
download-url = URL to download

download-http-headers = Additional HTTP headers for all HTTP requests, format is key: value
download-http-cookies =
    {"["}Advanced] Additional HTTP cookies

    Will not take effect if `Cookies` is set in `headers`.
    Do not use this option unless you know what you are doing.
download-http-timeout = HTTP timeout, in seconds
download-http-http1-only = Force to use HTTP/1.1 for requests

download-concurrency = Threads limit
download-segment-retries = Segment retry limit
# download-segment-retry-delay = Set retry delay after download fails in seconds
download-manifest-retries = Manifest retry limit

download-cache-in-menory-cache = Use in-memory cache and do not write cache to disk while downloading
download-cache-temp-dir =
  Temporary directory

  The default temp dir is the current directory or the system temp dir.
  Will not take effect if `cache_dir` is set.
download-cache-cache-dir =
    {"["}Advanced] Cache directory

    Speficy a directory to store cache files.

    If specified, the cache will be stored in this directory directly without creating a subdirectory.

download-output-no-merge = Do not merge stream
download-output-concat = Merge files using concat
download-output-output = Output filename
download-output-pipe = Pipe to stdout
download-output-pipe-mux = Mux with ffmpeg. Only works when `--pipe` is set.
download-output-pipe-to = Pipe to a file
download-output-pipe-keep-segments = When using pipe output, keep downloaded segments.