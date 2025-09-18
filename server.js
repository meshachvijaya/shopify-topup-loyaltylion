import express from "express";
import crypto from "crypto";
import { Pool } from "pg";

const app = express();
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Verifikasi signature App Proxy (HMAC-SHA256 dari query params selain 'signature')
function verifyAppProxySignature(req) {
    const url = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
    const params = url.searchParams;
    const signature = params.get("signature");
    if (!signature) return false;

    // Kumpulkan semua key (termasuk yang berulang), kecuali 'signature'
    const keys = Array.from(new Set([...params.keys()])).filter(k => k !== "signature").sort();

    const pairs = [];
    for (const k of keys) {
        const all = params.getAll(k);
        // Shopify menandatangani repeated query sebagai "k=v1,v2" dan menjaga nilai kosong ("")
        const value = all.length > 1 ? all.join(",") : (all[0] ?? "");
        pairs.push(`${k}=${value}`);
    }

    const data = pairs.join("&");
    const expected = crypto.createHmac("sha256", process.env.SHOPIFY_APP_SECRET).update(data).digest("hex");

    // Hindari timing attack
    try {
        return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    } catch {
        return false;
    }
}

// Endpoint healthcheck
app.get("/proxy/ping", (req, res) => res.json({ ok: true }));

// Redeem voucher
app.post("/proxy/redeem", async (req, res) => {
    try {
        if (!verifyAppProxySignature(req)) {
            return res.status(401).json({ ok: false, error: "invalid_signature" });
        }

        // Ambil Shopify customer ID dari App Proxy
        const url = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
        const customerId = url.searchParams.get("logged_in_customer_id");
        if (!customerId) {
            return res.status(401).json({ ok: false, error: "login_required" });
        }

        const code = (req.body?.code || "").trim();
        if (!code) return res.status(400).json({ ok: false, error: "missing_code" });

        const client = await pool.connect();

        try {
            await client.query("BEGIN");

            // Lock row + validasi 1x pakai
            const { rows } = await client.query(
                "SELECT id, points, used_at FROM vouchers WHERE code = $1 FOR UPDATE",
                [code]
            );
            if (rows.length === 0) {
                await client.query("ROLLBACK");
                return res.status(404).json({ ok: false, error: "code_not_found" });
            }
            const row = rows[0];
            if (row.used_at) {
                await client.query("ROLLBACK");
                return res.status(409).json({ ok: false, error: "code_already_used" });
            }

            // Tambah poin di LoyaltyLion (merchant_id = Shopify customer ID)
            const resp = await fetch(`https://api.loyaltylion.com/v2/customers/${encodeURIComponent(customerId)}/points`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${process.env.LOYALTYLION_API_KEY}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ points: row.points, reason: `Voucher ${code}` })
            });

            if (!resp.ok) {
                const detail = await resp.text();
                await client.query("ROLLBACK");
                return res.status(502).json({ ok: false, error: "loyaltylion_error", detail });
            }

            // Tandai voucher sebagai 'used'
            await client.query(
                "UPDATE vouchers SET used_at = NOW(), used_by_customer_id = $1 WHERE id = $2",
                [customerId, row.id]
            );

            await client.query("COMMIT");
            return res.json({ ok: true, points: row.points });
        } catch (e) {
            await client.query("ROLLBACK");
            throw e;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: "server_error" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));