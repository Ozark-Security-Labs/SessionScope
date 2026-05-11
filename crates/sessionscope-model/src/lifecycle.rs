#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleStage {
    Issue,
    Store,
    Transmit,
    Validate,
    Refresh,
    Revoke,
    Expire,
    Introspect,
}
