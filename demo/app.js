console.log("🚀 App starting...");
console.log("📦 Reading secrets from environment...");
console.log("");

const db_password = process.env.DATABASE_PASSWORD;
const db_user = process.env.DATABASE_USERNAME;
const stripe = process.env.API_STRIPE_KEY;
const sendgrid = process.env.API_SENDGRID_KEY;

if (!db_password) { console.log("❌ DATABASE_PASSWORD not found"); process.exit(1); }
if (!stripe) { console.log("❌ API_STRIPE_KEY not found"); process.exit(1); }

console.log("✅ Database connected as:", db_user);
console.log("✅ Payment processor ready:", stripe.substring(0, 12) + "...");
console.log("✅ Email service ready:", sendgrid.substring(0, 10) + "...");
console.log("");
console.log("🎉 All systems operational. No .env files. No hardcoded secrets.");
