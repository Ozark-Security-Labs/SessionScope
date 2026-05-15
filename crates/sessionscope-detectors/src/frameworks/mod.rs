//! Shared framework coverage notes for detector modules.
//!
//! Framework-specific evidence remains in the source detector family that owns
//! the artifact type: cookies, JWTs, sessions, bearer tokens, query parameters,
//! reset tokens, or refresh lifecycle. This module centralizes the framework
//! names used by those detectors so fixture assertions and documentation use the
//! same vocabulary.

pub const NEXTJS: &str = "nextjs";
pub const EXPRESS: &str = "express";
pub const FASTAPI: &str = "fastapi";
pub const DJANGO: &str = "django";

pub const ISSUE_18_FRAMEWORKS: [&str; 4] = [NEXTJS, EXPRESS, FASTAPI, DJANGO];
