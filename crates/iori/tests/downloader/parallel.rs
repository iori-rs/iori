use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures::{Stream, stream};
use iori::{
    IoriResult, StreamingSource,
    cache::memory::MemoryCacheSource,
    context::IoriContext,
    download::{ParallelDownloader, TracingApp},
    merge::SkipMerger,
};
use tokio::sync::oneshot;

use crate::source::{TestSegment, TestSource};

struct DelayedBatchSource {
    batches: Vec<Vec<TestSegment>>,
    delay: Duration,
}

impl DelayedBatchSource {
    fn new(batches: Vec<Vec<TestSegment>>, delay: Duration) -> Self {
        Self { batches, delay }
    }
}

impl StreamingSource for DelayedBatchSource {
    type Segment = TestSegment;

    async fn segments_stream(
        &self,
        _: &IoriContext,
    ) -> IoriResult<impl Stream<Item = IoriResult<Vec<Self::Segment>>>> {
        let batches = self.batches.clone();
        let delay = self.delay;
        Ok(Box::pin(stream::unfold(
            (0usize, batches),
            move |(idx, batches)| async move {
                if idx > 0 {
                    tokio::time::sleep(delay).await;
                }
                batches
                    .get(idx)
                    .cloned()
                    .map(|batch| (Ok(batch), (idx + 1, batches)))
            },
        )))
    }
}

#[tokio::test]
async fn test_parallel_downloader_with_failed_retry() -> anyhow::Result<()> {
    let source = TestSource::new(vec![
        TestSegment::new(1, 1, "test.ts".to_string()).with_fail_count(2),
    ]);

    let cache = Arc::new(MemoryCacheSource::new());

    ParallelDownloader::builder(Default::default())
        .app(TracingApp::default())
        .merger(SkipMerger)
        .cache(cache.clone())
        .retries(1)
        .ctrlc_handler()
        .download(source)
        .await?;

    let result = cache.into_inner();
    let result = result.lock().unwrap();
    assert_eq!(result.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_with_success_retry() -> anyhow::Result<()> {
    let source = TestSource::new(vec![
        TestSegment::new(1, 1, "test.ts".to_string()).with_fail_count(2),
    ]);

    let cache = Arc::new(MemoryCacheSource::new());

    ParallelDownloader::builder(Default::default())
        .app(TracingApp::default())
        .merger(SkipMerger)
        .cache(cache.clone())
        .retries(3)
        .ctrlc_handler()
        .download(source)
        .await?;

    let result = cache.into_inner();
    let result = result.lock().unwrap();
    assert_eq!(result.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_concurrency() -> anyhow::Result<()> {
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let max_concurrent = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let segments = (0..10)
        .map(|i| {
            TestSegment::new(1, i, format!("test{}.ts", i))
                .with_delay(Duration::from_millis(100))
                .with_counters(counter.clone(), max_concurrent.clone())
        })
        .collect::<Vec<_>>();

    let source = TestSource::new(segments);
    let cache = Arc::new(MemoryCacheSource::new());

    ParallelDownloader::builder(Default::default())
        .app(TracingApp::default())
        .merger(SkipMerger)
        .cache(cache.clone())
        .concurrency(NonZeroU32::new(5).unwrap())
        .ctrlc_handler()
        .download(source)
        .await?;

    // Max concurrency should be at most 5
    let max = max_concurrent.load(Ordering::SeqCst);
    println!("Max concurrent: {}", max);
    assert!(max <= 5);
    assert!(max > 1);

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_stop_signal() -> anyhow::Result<()> {
    let segments = (0..10)
        .map(|i| {
            TestSegment::new(1, i, format!("test{}.ts", i)).with_delay(Duration::from_millis(100))
        })
        .collect::<Vec<_>>();

    let source = TestSource::new(segments);
    let cache = Arc::new(MemoryCacheSource::new());
    let (tx, rx) = oneshot::channel();

    let downloader_handle = tokio::spawn(async move {
        ParallelDownloader::builder(Default::default())
            .app(TracingApp::default())
            .merger(SkipMerger)
            .cache(cache.clone())
            .stop_signal(rx)
            .download(source)
            .await
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    tx.send(()).unwrap();

    let res = downloader_handle.await?;
    assert!(res.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_empty_stream() -> anyhow::Result<()> {
    let source = TestSource::new(vec![]);
    let cache = Arc::new(MemoryCacheSource::new());

    ParallelDownloader::builder(Default::default())
        .app(TracingApp::default())
        .merger(SkipMerger)
        .cache(cache.clone())
        .ctrlc_handler()
        .download(source)
        .await?;

    let result = cache.into_inner();
    let result = result.lock().unwrap();
    assert_eq!(result.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_live_simulation() -> anyhow::Result<()> {
    let batch1 = vec![TestSegment::new(1, 0, "test0.ts".to_string())];
    let batch2 = vec![TestSegment::new(1, 1, "test1.ts".to_string())];

    let source = TestSource::new_with_batches(vec![batch1, batch2]);
    let cache = Arc::new(MemoryCacheSource::new());

    ParallelDownloader::builder(Default::default())
        .app(TracingApp::default())
        .merger(SkipMerger)
        .cache(cache.clone())
        .ctrlc_handler()
        .download(source)
        .await?;

    let result = cache.into_inner();
    let result = result.lock().unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains_key(&(0, 1)));
    assert!(result.contains_key(&(1, 1)));

    Ok(())
}

#[tokio::test]
async fn test_parallel_downloader_stop_signal_during_live_wait() -> anyhow::Result<()> {
    let batch1 = vec![TestSegment::new(1, 0, "test0.ts".to_string())];
    let batch2 = vec![TestSegment::new(1, 1, "test1.ts".to_string())];
    let source = DelayedBatchSource::new(vec![batch1, batch2], Duration::from_secs(60));
    let cache = Arc::new(MemoryCacheSource::new());
    let (tx, rx) = oneshot::channel();

    let downloader_handle = tokio::spawn(async move {
        ParallelDownloader::builder(Default::default())
            .app(TracingApp::default())
            .merger(SkipMerger)
            .cache(cache.clone())
            .stop_signal(rx)
            .download(source)
            .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    tx.send(()).unwrap();

    let res = tokio::time::timeout(Duration::from_secs(2), downloader_handle).await?;
    assert!(res?.is_ok());

    Ok(())
}
