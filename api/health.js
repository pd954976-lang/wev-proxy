const APP_VERSION = "2.0.0";

export default function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");
  response.status(200).json({
    ok: true,
    service: "private-web-relay",
    version: APP_VERSION,
    configured: Boolean((process.env.RELAY_API_KEY || "").trim()),
    time: new Date().toISOString()
  });
}
