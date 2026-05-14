//! Shared provider/library coverage vocabulary for detector modules.
//!
//! Provider/library adapters remain evidence-bound and offline. These constants
//! keep provider hints and fixture assertions aligned without implying that a
//! provider-managed runtime behavior is fully known from static source alone.

pub const AUTHJS: &str = "authjs";
pub const NEXTAUTH: &str = "nextauth";
pub const PASSPORT: &str = "passport";
pub const OAUTH: &str = "oauth";
pub const OIDC: &str = "oidc";
pub const AUTH0: &str = "auth0";
pub const OKTA: &str = "okta";
pub const COGNITO: &str = "cognito";
pub const AZURE_AD: &str = "azure-ad";
pub const FIREBASE: &str = "firebase";
pub const SUPABASE: &str = "supabase";
pub const CLERK: &str = "clerk";
pub const PROVIDER: &str = "provider";

pub const ISSUE_27_PROVIDERS: [&str; 13] = [
    AUTHJS, NEXTAUTH, PASSPORT, OAUTH, OIDC, AUTH0, OKTA, COGNITO, AZURE_AD, FIREBASE, SUPABASE,
    CLERK, PROVIDER,
];
