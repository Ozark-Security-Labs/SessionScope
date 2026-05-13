export async function serverApiKeyCall() {
  const apiKey = process.env.API_KEY;
  return fetch("https://billing.example.invalid/api", {
    headers: { "X-API-Key": apiKey },
  });
}
