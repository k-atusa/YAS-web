async function run() {
  const r = await fetch("http://localhost:7001/api/files/upload", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE3NzY2MDU2MjB9.J7PrZjR6xRLjtslxdLg2oejzY_rqypbRcAK7dRWKRtg"
    },
    body: JSON.stringify({ filename: "foo", encryptedData: "eD0=", expiresAt: "2026-06-20T12:00:00.000Z" })
  });
  console.log(r.status, await r.text());
}
run();
