package com.keyorix;

// Coverage-free random / mutation driver for JsonParser (the fallback of mechanism B, and a cross-check of Jazzer).
// Usage: java -Xmx512m -cp <classes>:<gson> com.keyorix.PlainFuzz <seed-from> <seed-to> [corpus dir of JSONTestSuite files]

import com.google.gson.JsonElement;
import com.google.gson.stream.JsonReader;
import com.google.gson.Strictness;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class PlainFuzz {
    private PlainFuzz() {}

    /** True when s is a single valid JSON text under Gson's STRICT mode (RFC 8259 reference). */
    static boolean valid(String s) {
        try (JsonReader r = new JsonReader(new StringReader(s))) {
            r.setStrictness(Strictness.STRICT);
            HostileJson.GSON.getAdapter(JsonElement.class).read(r);
            return r.peek() == com.google.gson.stream.JsonToken.END_DOCUMENT;
        } catch (Throwable t) {
            return false;
        }
    }

    static final Map<String, Integer> COUNT = new TreeMap<>();
    static final Map<String, String> EXAMPLE = new TreeMap<>();

    static void record(String sig, String example) {
        COUNT.merge(sig, 1, Integer::sum);
        EXAMPLE.putIfAbsent(sig, example);
    }

    static String sigOf(String v) {
        // keep function name and category, drop values
        String[] p = v.split(" ");
        return p.length > 1 ? p[0] + " " + p[1] : p[0];
    }

    static String corrupt(HostileJson.Src s, String doc) {
        switch (s.n(6)) {
            case 0: return doc.substring(0, s.n(Math.max(1, doc.length())));                      // truncate
            case 1: { int i = s.n(Math.max(1, doc.length())); return doc.substring(0, i) + doc.substring(Math.min(doc.length(), i + 1)); } // delete a char
            case 2: { int i = s.n(Math.max(1, doc.length())); return doc.substring(0, i) + "}" + doc.substring(i); }                   // stray brace
            case 3: { int i = s.n(Math.max(1, doc.length())); return doc.substring(0, i) + "," + doc.substring(i); }                   // stray comma
            case 4: return doc + " trailing";
            default: return doc.replaceFirst("\"", "'");
        }
    }

    static void timed(List<String> out, String what, Runnable r) {
        long t0 = System.nanoTime();
        r.run();
        long ms = (System.nanoTime() - t0) / 1_000_000;
        if (ms > 1000) out.add("hang " + what + " " + ms + "ms");
    }

    public static void main(String[] args) throws Exception {
        long from = Long.parseLong(args[0]), to = Long.parseLong(args[1]);
        long t0 = System.currentTimeMillis();
        long docs = 0, invalidDocs = 0;
        int[] acceptedInvalid = new int[6], totalInvalid = new int[6];
        for (long seed = from; seed <= to; seed++) {
            HostileJson.Src s = new HostileJson.RandSrc(seed);
            boolean nasty = s.b(), conformant = s.b();
            var root = HostileJson.genDoc(s, nasty, conformant);
            String doc = s.b() ? HostileJson.PRETTY.toJson(root) : HostileJson.GSON.toJson(root);
            docs++;
            List<String> v = HostileJson.check(doc, root, conformant);
            for (String x : v) record((conformant ? "valid/conformant " : "valid/nonconformant ") + (nasty ? "nasty " : "plain ") + sigOf(x), "seed=" + seed + " " + x + " doc=" + trunc(doc, 300));
            // invalid inputs: the parser should not hand back data from a document that is not valid JSON
            for (int k = 0; k < 3; k++) {
                int kind = s.n(6);
                String bad = null;
                HostileJson.Src s2 = new HostileJson.RandSrc(seed * 31 + k);
                switch (kind) {
                    case 0: bad = doc.substring(0, s2.n(Math.max(1, doc.length()))); break;
                    default: bad = corrupt(s2, doc);
                }
                if (valid(bad)) continue;
                invalidDocs++;
                totalInvalid[kind]++;
                List<String> o = new ArrayList<>();
                final String fb = bad;
                boolean[] accepted = {false};
                HostileJson.guard(o, "parseSecretValue", () -> { if (JsonParser.parseSecretValue(fb) != null) accepted[0] = true; });
                HostileJson.guard(o, "parseSecretList", () -> { if (!JsonParser.parseSecretList(fb).isEmpty()) accepted[0] = true; });
                HostileJson.guard(o, "parseProjectList", () -> { if (!JsonParser.parseProjectList(fb).isEmpty()) accepted[0] = true; });
                HostileJson.guard(o, "parseTotalPages", () -> { if (JsonParser.parseTotalPages(fb) != 0) accepted[0] = true; });
                for (String x : o) record("invalid-input " + sigOf(x), "seed=" + seed + " " + x + " doc=" + trunc(fb, 200));
                if (accepted[0]) acceptedInvalid[kind]++;
            }
        }
        // size and depth bombs: no StackOverflowError, no OOM, no hang
        for (int depth : new int[]{1000, 100000, 1000000}) {
            for (String kind : new String[]{"arr", "obj"}) {
                String open = kind.equals("arr") ? "[" : "{\"a\":", close = kind.equals("arr") ? "]" : "}";
                String doc = "{\"data\":{\"x\":" + open.repeat(depth) + (kind.equals("arr") ? "" : "1") + close.repeat(depth) + ",\"value\":\"ok\",\"secrets\":[{\"name\":\"n\",\"id\":1}],\"total_pages\":2}}";
                List<String> o = new ArrayList<>();
                timed(o, "bomb-" + kind + depth, () -> {
                    HostileJson.guard(o, "bomb-" + kind + depth, () -> {
                        JsonParser.parseSecretValue(doc);
                        JsonParser.parseSecretList(doc);
                        JsonParser.parseTotalPages(doc);
                    });
                });
                for (String x : o) record("bomb " + x.split(" ")[0] + " " + kind + depth, x);
            }
        }
        String big = "A".repeat(50_000_000);
        List<String> o2 = new ArrayList<>();
        timed(o2, "bigstring", () -> HostileJson.guard(o2, "bigstring", () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"" + big + "\"}}")));
        String many = "{\"data\":{\"secrets\":[" + "{\"name\":\"n\",\"id\":1},".repeat(300_000) + "{\"name\":\"n\",\"id\":1}],\"total_pages\":1}}";
        timed(o2, "manyitems", () -> HostileJson.guard(o2, "manyitems", () -> JsonParser.parseSecretList(many)));
        for (String x : o2) record("bomb " + x.split(" ")[0], x);

        System.out.printf("PlainFuzz seeds %d..%d: %d valid documents, %d invalid inputs, %.0fs%n", from, to, docs, invalidDocs, (System.currentTimeMillis() - t0) / 1000.0);
        String[] kn = {"truncate", "delete-char", "stray-brace", "stray-comma", "trailing-garbage", "single-quote"};
        for (int i = 0; i < 6; i++) System.out.printf("invalid kind %-17s: %d inputs, parser returned data for %d%n", kn[i], totalInvalid[i], acceptedInvalid[i]);
        COUNT.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
            .forEach(e -> System.out.printf("%7d  %s%n         e.g. %s%n", e.getValue(), e.getKey(), EXAMPLE.get(e.getKey())));
        if (args.length > 2) corpus(Path.of(args[2]));
    }

    static String trunc(String s, int n) { return s.length() > n ? s.substring(0, n) + "..." : s; }

    /** JSONTestSuite probe of the Java extractor: content embedded before a real value; accept means the real value was still returned. */
    static void corpus(Path dir) throws Exception {
        List<Path> files = new ArrayList<>();
        try (var st = Files.list(dir)) { st.filter(p -> p.getFileName().toString().endsWith(".json")).sorted(Comparator.naturalOrder()).forEach(files::add); }
        int[][] tab = new int[3][4]; // y,n,i x {accepted, rejected, gson-ok, gson-no}
        List<String> devs = new ArrayList<>();
        for (Path p : files) {
            String name = p.getFileName().toString();
            int row = name.charAt(0) == 'y' ? 0 : name.charAt(0) == 'n' ? 1 : 2;
            String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            String doc = "{\"data\":{\"x\":" + content + ",\"value\":\"ok\"}}";
            boolean acc;
            try { acc = "ok".equals(JsonParser.parseSecretValue(doc)); } catch (Throwable t) { acc = false; devs.add(name + " threw " + t); }
            tab[row][acc ? 0 : 1]++;
            tab[row][valid(content) ? 2 : 3]++;
            if ((row == 0 && !acc) || (row == 1 && acc && devs.size() < 400)) devs.add(name + (acc ? " accepted(invalid)" : " rejected(valid)"));
        }
        System.out.println("-- JSONTestSuite probe, Java JsonParser.parseSecretValue on {\"data\":{\"x\":<file>,\"value\":\"ok\"}} (accept = real value still returned)");
        String[] rn = {"y_ (must accept)", "n_ (must reject)", "i_ (record)"};
        for (int i = 0; i < 3; i++) System.out.printf("%-17s accepted=%d rejected=%d | Gson STRICT on the file alone: ok=%d no=%d%n", rn[i], tab[i][0], tab[i][1], tab[i][2], tab[i][3]);
        int shown = 0;
        for (String d : devs) { if (shown++ < 12) System.out.println("   " + d); }
    }
}
