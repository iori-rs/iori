shiori-about = 又一个直播下载器

download-wait = 当未检测到直播流时，是否等待直播流开始
download-url = 视频地址

download-http-headers = 设置 HTTP header，格式为 key: value
download-http-cookies =
  {"["}高级选项] 设置 Cookie

  当 headers 中有 Cookie 时，该选项不会生效。
  如果你不知道这个字段要如何使用，请不要设置它。
download-http-timeout = 下载超时时间，单位为秒
download-http-http1-only = 强制使用 HTTP/1.1 进行 http 请求

download-concurrency = 并发数
download-segment-retries = 分块下载重试次数
# download-segment-retry-delay = 设置下载失败后重试的延迟，单位为秒
download-manifest-retries = manifest 下载重试次数

download-cache-in-menory-cache = 使用内存缓存，下载时不将缓存写入磁盘
download-cache-temp-dir =
  临时目录

  默认临时目录是当前目录或系统临时目录。
  如果设置了 `cache_dir`，则此选项无效。
download-cache-cache-dir =
  {"["}高级选项] 缓存目录

  存储分块及下载时产生的临时文件的目录。
  文件会直接存储在该目录下，而不会创建子目录。为安全起见，请自行创建子目录。

download-output-no-merge = 跳过合并
download-output-concat = 使用 Concat 合并文件
download-output-output = 输出文件名
download-output-pipe = 输出到标准输出
download-output-pipe-mux = 使用 FFmpeg 混流，仅在 `--pipe` 生效时有效
download-output-pipe-to = 使用 Pipe 输出到指定路径
download-output-pipe-keep-segments = 使用 Pipe 输出时，保留已下载的分片。
