use std::convert::Infallible;
use std::io;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use bytes::BytesMut;
use compio::buf::{IoBuf, IoBufMut, SetLen};
use compio::{BufResult, time};
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};

/// Retries the async operation up to `attempts` times.
/// Uses `FnMut() -> Fut` with explicit `Fut: Send` bound so the future type is
/// not over-constrained by `AsyncFnMut` (which can trigger "Send not general enough").
#[inline]
pub async fn retry<T, E, F, Fut>(attempts: NonZeroUsize, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    for i in 0..attempts.get() {
        match f().await {
            Ok(res) => return Ok(res),
            Err(err) => {
                if i + 1 >= attempts.get() {
                    return Err(err);
                }
            }
        }
    }

    unreachable!("")
}

pub trait TimeoutExt: Future {
    async fn timeout(self, dur: Duration) -> io::Result<Self::Output>;
}

impl<F: Future> TimeoutExt for F {
    #[inline]
    async fn timeout(self, dur: Duration) -> io::Result<Self::Output> {
        time::timeout(dur, self)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::TimedOut, err))
    }
}

pub trait PartsExt {
    type Output;

    fn to_parts(self) -> Self::Output;
}

impl<T, B> PartsExt for BufResult<T, B> {
    type Output = (io::Result<T>, B);

    #[inline]
    fn to_parts(self) -> Self::Output {
        let BufResult(res, buf) = self;

        (res, buf)
    }
}

#[derive(Debug, Clone)]
pub struct BytesMutPool {
    pool: Pool<BytesMutManager>,
}

impl BytesMutPool {
    pub fn new(cap: usize) -> Self {
        Self {
            pool: Pool::builder(BytesMutManager { cap }).build().unwrap(),
        }
    }

    pub async fn get_bytes_mut(&self) -> BytesMutObject {
        BytesMutObject {
            obj: self.pool.get().await.unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct BytesMutObject {
    obj: Object<BytesMutManager>,
}

impl AsRef<[u8]> for BytesMutObject {
    fn as_ref(&self) -> &[u8] {
        self.as_init()
    }
}

impl AsMut<[u8]> for BytesMutObject {
    fn as_mut(&mut self) -> &mut [u8] {
        self.obj.as_mut_slice()
    }
}

impl Deref for BytesMutObject {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.obj.deref()
    }
}

impl DerefMut for BytesMutObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.obj.deref_mut()
    }
}

impl IoBuf for BytesMutObject {
    fn as_init(&self) -> &[u8] {
        self.obj.as_init()
    }
}

impl SetLen for BytesMutObject {
    unsafe fn set_len(&mut self, len: usize) {
        unsafe {
            self.obj.set_len(len);
        }
    }
}

impl IoBufMut for BytesMutObject {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        self.obj.as_uninit()
    }
}

#[derive(Debug)]
struct BytesMutManager {
    cap: usize,
}

impl Manager for BytesMutManager {
    type Type = BytesMut;
    type Error = Infallible;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        Ok(BytesMut::with_capacity(self.cap))
    }

    async fn recycle(
        &self,
        obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        obj.clear();
        obj.reserve(self.cap);

        Ok(())
    }
}
