// Supabase Edge Function: submit-request
// Deploy with verify_jwt=false; this endpoint is public by design but validates,
// rate-limits, and writes using the server-only service-role key.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigins = new Set(["https://webvault.cc", "https://www.webvault.cc"]);
const maxFileBytes = 25 * 1024 * 1024;
const allowedTypes = new Set([
  "image/jpeg", "image/png", "image/webp", "image/heic",
  "video/mp4", "video/quicktime", "video/webm",
]);

function cors(origin: string | null) {
  const permitted = origin && allowedOrigins.has(origin) ? origin : "https://webvault.cc";
  return {
    "Access-Control-Allow-Origin": permitted,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function json(data: unknown, status: number, origin: string | null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function sha256(value: string) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(origin) });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405, origin);
  if (origin && !allowedOrigins.has(origin)) return json({ error: "Origin not allowed" }, 403, origin);

  const ip = req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) return json({ error: "Server is not configured" }, 500, origin);

  const admin = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const form = await req.formData();
    // Hidden honeypot field. Real visitors should leave it empty.
    if (String(form.get("website") ?? "").trim()) return json({ ok: true }, 200, origin);

    const name = String(form.get("name") ?? "").trim().slice(0, 120);
    const contact = String(form.get("reach") ?? "").trim().slice(0, 180);
    const business = String(form.get("biz") ?? "").trim().slice(0, 180);
    const message = String(form.get("msg") ?? "").trim().slice(0, 4000);
    if (!name || !contact) return json({ error: "Name and contact are required." }, 400, origin);
    if (name.length < 2 || contact.length < 5) return json({ error: "Please check your details." }, 400, origin);

    const ipHash = await sha256(ip + (Deno.env.get("RATE_LIMIT_SALT") ?? ""));
    const { data: allowed, error: limitError } = await admin.rpc("webvault_allow_submission", { p_ip_hash: ipHash });
    if (limitError) throw limitError;
    if (!allowed) return json({ error: "Too many requests. Please try again later." }, 429, origin);

    const { data: requestRow, error: insertError } = await admin
      .from("customer_requests")
      .insert({ customer_name: name, contact, business, message })
      .select("id")
      .single();
    if (insertError) throw insertError;

    const files = form.getAll("files").filter((item): item is File => item instanceof File && item.size > 0);
    if (files.length > 5) {
      await admin.from("customer_requests").delete().eq("id", requestRow.id);
      return json({ error: "Please upload no more than five files." }, 400, origin);
    }

    for (const file of files) {
      if (file.size > maxFileBytes || !allowedTypes.has(file.type)) {
        await admin.from("customer_requests").delete().eq("id", requestRow.id);
        return json({ error: "One of the files is too large or has an unsupported type." }, 400, origin);
      }
      const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(-100) || "upload";
      const path = `${requestRow.id}/${crypto.randomUUID()}-${safeName}`;
      const { error: uploadError } = await admin.storage
        .from("webvault-private-uploads")
        .upload(path, file, { contentType: file.type, upsert: false });
      if (uploadError) {
        await admin.from("customer_requests").delete().eq("id", requestRow.id);
        throw uploadError;
      }
      const { error: fileRowError } = await admin.from("request_files").insert({
        request_id: requestRow.id,
        storage_path: path,
        original_name: safeName,
        content_type: file.type,
        size_bytes: file.size,
      });
      if (fileRowError) throw fileRowError;
    }

    return json({ ok: true, message: "Your request was received securely." }, 200, origin);
  } catch (error) {
    console.error("submit-request failed", error);
    return json({ error: "We couldn't submit your request. Please try again." }, 500, origin);
  }
});
