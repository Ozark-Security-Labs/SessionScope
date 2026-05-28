// Supabase Auth SDK token lifecycle: session read, refresh, and sign-out.
export async function supabaseSession() {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token;
}

export async function supabaseRefresh() {
  return supabase.auth.refreshSession({
    refresh_token: "PLACEHOLDER_RESET_TOKEN",
  });
}

export async function supabaseLogout() {
  await supabase.auth.signOut();
}
