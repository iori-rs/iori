use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc;

pub struct OrderedStream<T> {
    // stream_id -> sequence -> item
    buffer: HashMap<u64, BTreeMap<u64, T>>,
    // stream_id -> next_seq
    next_seq: HashMap<u64, u64>,
    // stream_id, sequence, item
    rx: mpsc::UnboundedReceiver<(u64, u64, T)>,
}

impl<T> OrderedStream<T> {
    pub fn new(rx: mpsc::UnboundedReceiver<(u64, u64, T)>) -> Self {
        Self {
            buffer: HashMap::new(),
            next_seq: HashMap::new(),
            rx,
        }
    }

    pub async fn next(&mut self) -> Option<(u64, T)> {
        loop {
            // Check if we have the next item in buffer for any stream
            for (stream_id, next_seq) in self.next_seq.iter_mut() {
                if let Some(stream_buffer) = self.buffer.get_mut(stream_id)
                    && let Some(item) = stream_buffer.remove(next_seq)
                {
                    *next_seq += 1;
                    return Some((*stream_id, item));
                }
            }

            // Receive new item
            match self.rx.recv().await {
                Some((stream_id, seq, item)) => {
                    // Initialize next_seq for new streams
                    let next_seq = self.next_seq.entry(stream_id).or_insert(0);

                    if seq == *next_seq {
                        *next_seq += 1;
                        return Some((stream_id, item));
                    } else {
                        // Store out-of-order item in the buffer
                        let stream_buffer = self.buffer.entry(stream_id).or_default();
                        stream_buffer.insert(seq, item);
                    }
                }
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_one_ordered_stream() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut ordered = OrderedStream::new(rx);

        // Send items out of order
        tokio::spawn(async move {
            tx.send((0, 2, "c")).unwrap();
            tx.send((0, 0, "a")).unwrap();
            tx.send((0, 1, "b")).unwrap();
            drop(tx);
        });

        // Receive items in order
        assert_eq!(ordered.next().await.unwrap(), (0, "a"));
        assert_eq!(ordered.next().await.unwrap(), (0, "b"));
        assert_eq!(ordered.next().await.unwrap(), (0, "c"));
        assert_eq!(ordered.next().await, None);
    }

    #[tokio::test]
    async fn test_mixed_ordered_streams() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut ordered = OrderedStream::new(rx);

        // Send items out of order
        tokio::spawn(async move {
            tx.send((0, 2, "c")).unwrap();
            tx.send((1, 0, "a")).unwrap();
            tx.send((0, 0, "a")).unwrap();
            tx.send((1, 1, "b")).unwrap();
            tx.send((0, 1, "b")).unwrap();
            tx.send((1, 2, "c")).unwrap();
            drop(tx);
        });

        // Receive items in order
        assert_eq!(ordered.next().await.unwrap(), (1, "a"));
        assert_eq!(ordered.next().await.unwrap(), (0, "a"));
        assert_eq!(ordered.next().await.unwrap(), (1, "b"));
        assert_eq!(ordered.next().await.unwrap(), (0, "b"));
        assert_eq!(ordered.next().await.unwrap(), (0, "c"));
        assert_eq!(ordered.next().await.unwrap(), (1, "c"));
        assert_eq!(ordered.next().await, None);
    }
}
