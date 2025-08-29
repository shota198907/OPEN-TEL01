
/**
 * Minimal smoke: requires OPENAI_E2E_EPHEMERAL_TOKEN (optional).
 * Otherwise, checks /health only.
 */
(async () => {
  const base = process.env.BASE_URL || "http://localhost:8080";
  const health = await fetch(`${base}/health`).then(r => r.json()).catch(()=>null);
  console.log("[E2E] /health =>", health ? "OK" : "NG");

  const EPHEMERAL = process.env.OPENAI_E2E_EPHEMERAL_TOKEN || "";
  if (!EPHEMERAL) {
    console.log("[E2E] Skipped /api/sdp (no token)");
    process.exit(0);
  }

  const csrf = await fetch(`${base}/api/csrf-token`, { credentials: 'include' }).then(r => r.json()).catch(()=>({}));
  const dummyOffer = `v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtpmap:111 opus/48000/2
a=sendrecv
a=mid:0
`;

  const r = await fetch(`${base}/api/sdp`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${EPHEMERAL}`, 'Content-Type': 'application/sdp', 'X-CSRF-Token': csrf.csrfToken || '' },
    body: dummyOffer
  });
  const text = await r.text();
  console.log("[E2E] /api/sdp status:", r.status, "len:", text.length);
  process.exit(0);
})();
