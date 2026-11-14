package com.keyorix;

// Mechanism B of the hostile-server mode (hostile/RULES.md section 8): direct fuzz of the SDK's hand-written
// JsonParser. This file lives in the package of the SDK only so that it can reach the package-private parser; it is
// compiled together with a copy of the SDK sources and never added to the SDK repository. Gson is a TEST-ONLY
// reference dependency (see fetch-tools.sh), never part of the SDK build.

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class HostileJson {
    private HostileJson() {}

    /** Source of choices: a Jazzer data provider or a seeded PRNG. */
    interface Src {
        int n(int bound);

        default boolean b() { return n(2) == 1; }

        default <T> T pick(T[] a) { return a[n(a.length)]; }
    }

    static final class RandSrc implements Src {
        final Random r;
        RandSrc(long seed) { r = new Random(seed); }
        public int n(int bound) { return r.nextInt(bound); }
    }

    static final class JazzSrc implements Src {
        final FuzzedDataProvider d;
        JazzSrc(FuzzedDataProvider d) { this.d = d; }
        public int n(int bound) { return d.consumeInt(0, bound - 1); }
    }

    static final String[] KEYS = {"data", "value", "token", "secrets", "projects", "environments", "deleted", "total_pages",
        "id", "name", "type", "project_id", "environment_name", "created_at", "description", "purge_at", "secret", "success",
        "message", "error", "environment", "x"};
    static final String[] PLAIN = {"a", "b", "z", "Q", "0", "7", " ", "_", "-", ".", "/", ":", "ab", "xyz", "prod", "db password"};
    static final String[] NASTY = {"\"", "\\", "\n", "\t", "\u0000", "é", "😀", "{", "}", "[", "]", ",", ":", "\"value\":\"zzz",
        "\\\"", " ", "\u007f"};
    static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    static final Gson PRETTY = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    static String genString(Src s, boolean nasty) {
        int len = s.n(7);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(nasty && s.n(3) == 0 ? s.pick(NASTY) : s.pick(PLAIN));
        }
        return sb.toString();
    }

    static JsonElement genScalar(Src s, boolean nasty) {
        switch (s.n(6)) {
            case 0: return new JsonPrimitive(s.n(1000));
            case 1: return new JsonPrimitive(9007199254740993L + s.n(3));
            case 2: return new JsonPrimitive(s.b());
            case 3: return com.google.gson.JsonNull.INSTANCE;
            default: return new JsonPrimitive(genString(s, nasty));
        }
    }

    static JsonElement genAny(Src s, int depth, boolean nasty) {
        if (depth <= 0 || s.n(3) == 0) return genScalar(s, nasty);
        if (s.b()) {
            JsonArray a = new JsonArray();
            for (int i = 0, n = s.n(3); i < n; i++) a.add(genAny(s, depth - 1, nasty));
            return a;
        }
        return genObject(s, depth - 1, nasty, null);
    }

    static JsonObject genObject(Src s, int depth, boolean nasty, String[] must) {
        Map<String, JsonElement> m = new LinkedHashMap<>();
        List<String> ks = new ArrayList<>();
        if (must != null) for (String k : must) ks.add(k);
        for (int i = 0, n = s.n(4); i < n; i++) ks.add(s.pick(KEYS));
        for (int i = ks.size() - 1; i > 0; i--) {
            int j = s.n(i + 1);
            String t = ks.get(i); ks.set(i, ks.get(j)); ks.set(j, t);
        }
        for (String k : ks) m.put(k, genAny(s, depth, nasty));
        JsonObject o = new JsonObject();
        for (Map.Entry<String, JsonElement> e : m.entrySet()) o.add(e.getKey(), e.getValue());
        return o;
    }

    static JsonObject genItem(Src s, boolean nasty, boolean conformant) {
        JsonObject o = new JsonObject();
        List<String> kv = new ArrayList<>(List.of("id", "name", "type", "project_id", "environment_name", "created_at", "description", "purge_at"));
        for (int i = kv.size() - 1; i > 0; i--) { int j = s.n(i + 1); String t = kv.get(i); kv.set(i, kv.get(j)); kv.set(j, t); }
        for (String key : kv) {
            if (s.n(5) == 0) continue;
            boolean numeric = key.equals("id") || key.equals("project_id");
            if (numeric) {
                o.add(key, conformant || s.n(4) != 0 ? new JsonPrimitive(s.n(100000)) : genAny(s, 2, nasty));
            } else {
                o.add(key, conformant || s.n(4) != 0 ? new JsonPrimitive(genString(s, nasty)) : genAny(s, 2, nasty));
            }
            if (s.n(6) == 0) o.add(s.pick(KEYS), genAny(s, 2, nasty));
        }
        if (s.n(5) == 0) o.add("secret", genObject(s, 1, nasty, new String[]{"id", "name", "value"}));
        return o;
    }

    /** One generated response: {"success":true,"data":{...}} with random key order, noise and whitespace. */
    static JsonObject genDoc(Src s, boolean nasty, boolean conformant) {
        JsonObject data = new JsonObject();
        List<String> keys = new ArrayList<>(List.of("value", "token", "secrets", "projects", "environments", "deleted", "total_pages", "x", "secret"));
        for (int i = keys.size() - 1; i > 0; i--) { int j = s.n(i + 1); String t = keys.get(i); keys.set(i, keys.get(j)); keys.set(j, t); }
        for (String k : keys) {
            if (s.n(3) == 0) continue;
            switch (k) {
                case "value": case "token":
                    data.add(k, conformant || s.n(4) != 0 ? new JsonPrimitive(genString(s, nasty)) : genAny(s, 2, nasty));
                    break;
                case "total_pages":
                    data.add(k, conformant || s.n(4) != 0 ? new JsonPrimitive(s.n(50)) : genAny(s, 1, nasty));
                    break;
                case "secrets": case "projects": case "environments": case "deleted": {
                    if (!conformant && s.n(5) == 0) { data.add(k, genAny(s, 2, nasty)); break; }
                    JsonArray a = new JsonArray();
                    for (int i = 0, n = s.n(4); i < n; i++) a.add(genItem(s, nasty, conformant));
                    data.add(k, a);
                    break;
                }
                case "secret": data.add(k, genObject(s, 2, nasty, new String[]{"id", "name", "value"})); break;
                default: data.add(k, genAny(s, 3, nasty));
            }
        }
        JsonObject root = new JsonObject();
        if (s.b()) root.addProperty("success", true);
        if (s.n(6) == 0) root.add("message", genAny(s, 2, nasty));
        root.add("data", data);
        if (s.n(6) == 0) root.add("x", genAny(s, 3, nasty));
        return root;
    }

    // ---- reference extraction ----

    static String refString(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString() ? e.getAsString() : null;
    }

    static long refLong(JsonObject o, String key) {
        JsonElement e = o.get(key);
        if (e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isNumber()) {
            try { return new java.math.BigDecimal(e.getAsString()).longValueExact(); } catch (ArithmeticException | NumberFormatException x) { return 0; }
        }
        return 0;
    }

    static String nz(String s) { return s == null ? "" : s; }

    static List<JsonElement> arr(JsonObject data, String key) {
        List<JsonElement> l = new ArrayList<>();
        JsonElement e = data.get(key);
        if (e != null && e.isJsonArray()) for (JsonElement x : e.getAsJsonArray()) l.add(x);
        return l;
    }

    interface Body { void run(); }

    interface Check { String run(); }

    /** Any Throwable out of a parser method is a violation (the parser declares none; KeyorixException is its only declared type). */
    static void guard(List<String> out, String what, Body b) {
        try {
            b.run();
        } catch (Throwable t) {
            if (t instanceof KeyorixException) return; // declared SDK type: acceptable
            out.add(what + " threw " + t.getClass().getName() + ": " + String.valueOf(t.getMessage()).replace("\n", " "));
        }
    }

    static String q(String s) { return s == null ? "null" : "\"" + (s.length() > 60 ? s.substring(0, 60) + "..." : s).replace("\n", "\\n") + "\""; }

    /** Cause category used to de-duplicate divergences. */
    static String cat(String exp, String got) {
        if (exp != null && (exp.indexOf('\\') >= 0 || exp.indexOf('"') >= 0 || exp.chars().anyMatch(c -> c < 0x20))) return "escape";
        if (got != null && exp == null) return "wrong-scope";
        if (got == null && exp != null) return "missed";
        return "scope";
    }

    static void strCheck(List<String> out, String fn, String got, String exp, boolean conformant) {
        if (conformant) {
            if (!java.util.Objects.equals(got, exp)) out.add(fn + " " + cat(exp, got) + " exp=" + q(exp) + " got=" + q(got));
        } else if (exp == null && got != null) {
            out.add(fn + " wrong-type-yields-string exp=null got=" + q(got));
        } else if (exp != null && got != null && !got.equals(exp)) {
            out.add(fn + " " + cat(exp, got) + " exp=" + q(exp) + " got=" + q(got));
        }
    }

    static void listCheck(List<String> out, JsonObject data, String key, boolean conformant, Check c) {
        guard(out, "parse-" + key, () -> {
            String d = c.run();
            JsonElement e = data.get(key);
            boolean wrongType = e != null && !e.isJsonArray();
            if (d != null && (conformant || !wrongType)) out.add("parse-" + key + " " + d);
            if (d != null && !conformant && wrongType) out.add("parse-" + key + " wrong-type-yields-list " + d);
        });
    }

    static String cmp(List<String[]> exp, List<String[]> got) {
        if (exp.size() != got.size()) return "count exp=" + exp.size() + " got=" + got.size();
        for (int i = 0; i < exp.size(); i++) {
            if (!java.util.Arrays.equals(exp.get(i), got.get(i))) return "item" + i + " exp=" + java.util.Arrays.toString(exp.get(i)) + " got=" + java.util.Arrays.toString(got.get(i));
        }
        return null;
    }

    /** Divergences between JsonParser and the reference extraction for a valid document. */
    static List<String> check(String doc, JsonObject root, boolean conformant) {
        List<String> out = new ArrayList<>();
        JsonObject data = root.get("data").getAsJsonObject();
        guard(out, "parseSecretValue", () -> strCheck(out, "parseSecretValue", JsonParser.parseSecretValue(doc), refString(data, "value"), conformant));
        guard(out, "parseToken", () -> strCheck(out, "parseToken", JsonParser.parseToken(doc), refString(data, "token"), conformant));
        guard(out, "parseTotalPages", () -> {
            int got = JsonParser.parseTotalPages(doc);
            JsonElement tp = data.get("total_pages");
            boolean isNum = tp != null && tp.isJsonPrimitive() && tp.getAsJsonPrimitive().isNumber();
            long exp = isNum ? refLong(data, "total_pages") : 0;
            if (conformant && got != exp) out.add("parseTotalPages scope exp=" + exp + " got=" + got);
            if (!conformant && tp != null && !isNum && got != 0) out.add("parseTotalPages wrong-type-yields-number got=" + got);
        });
        listCheck(out, data, "secrets", conformant, () -> {
            List<Secret> got = JsonParser.parseSecretList(doc);
            List<String[]> exp = new ArrayList<>();
            for (JsonElement e : arr(data, "secrets")) {
                if (!e.isJsonObject()) continue;
                JsonObject o = e.getAsJsonObject();
                String name = refString(o, "name");
                if (name == null) continue;
                exp.add(new String[]{String.valueOf(refLong(o, "id")), name, nz(refString(o, "type")), nz(refString(o, "environment_name")),
                    String.valueOf(refLong(o, "project_id")), nz(refString(o, "created_at"))});
            }
            List<String[]> g = new ArrayList<>();
            for (Secret x : got) g.add(new String[]{String.valueOf(x.getId()), x.getName(), x.getType(), x.getEnvironment(), String.valueOf(x.getProjectId()), x.getCreatedAt()});
            return cmp(exp, g);
        });
        listCheck(out, data, "projects", conformant, () -> {
            List<Project> got = JsonParser.parseProjectList(doc);
            List<String[]> exp = new ArrayList<>();
            for (JsonElement e : arr(data, "projects")) {
                if (!e.isJsonObject()) continue;
                JsonObject o = e.getAsJsonObject();
                String name = refString(o, "name");
                if (name == null) continue;
                exp.add(new String[]{String.valueOf(refLong(o, "id")), name, nz(refString(o, "description")), nz(refString(o, "created_at"))});
            }
            List<String[]> g = new ArrayList<>();
            for (Project x : got) g.add(new String[]{String.valueOf(x.getId()), x.getName(), x.getDescription(), x.getCreatedAt()});
            return cmp(exp, g);
        });
        listCheck(out, data, "environments", conformant, () -> {
            List<Environment> got = JsonParser.parseEnvironmentList(doc);
            List<String[]> exp = new ArrayList<>();
            for (JsonElement e : arr(data, "environments")) {
                if (!e.isJsonObject()) continue;
                JsonObject o = e.getAsJsonObject();
                String name = refString(o, "name");
                if (name == null) continue;
                exp.add(new String[]{String.valueOf(refLong(o, "id")), String.valueOf(refLong(o, "project_id")), name});
            }
            List<String[]> g = new ArrayList<>();
            for (Environment x : got) g.add(new String[]{String.valueOf(x.getId()), String.valueOf(x.getProjectId()), x.getName()});
            return cmp(exp, g);
        });
        return out;
    }

    // ---- Jazzer entry point ----

    /** Signatures already triaged; -Dhj.ignore=a,b makes the run continue to the next class of divergence. */
    static final String[] IGNORE = System.getProperty("hj.ignore", "").split(",");

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Src s = new JazzSrc(data);
        boolean nasty = s.b(), conformant = s.b();
        JsonObject root = genDoc(s, nasty, conformant);
        String doc = s.b() ? PRETTY.toJson(root) : GSON.toJson(root);
        List<String> v = new ArrayList<>();
        for (String x : check(doc, root, conformant)) {
            boolean ignored = false;
            for (String ig : IGNORE) if (!ig.isEmpty() && x.contains(ig)) ignored = true;
            if (!ignored) v.add(x);
        }
        if (!v.isEmpty()) throw new AssertionError(v.get(0) + "\n  doc=" + (doc.length() > 400 ? doc.substring(0, 400) : doc));
    }
}
