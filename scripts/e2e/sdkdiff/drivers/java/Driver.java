import com.keyorix.AuthException;
import com.keyorix.Keyorix;
import com.keyorix.KeyorixClient;
import com.keyorix.KeyorixException;
import com.keyorix.Secret;
import com.keyorix.SecretNotFoundException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Duration;
import java.util.List;

/** Driver for the Keyorix Java SDK. One protocol line in, one JSON line out (see ../../PROTOCOL.md). */
public class Driver {
    static final String PLANT = System.getenv("SDKDIFF_PLANT") == null ? "" : System.getenv("SDKDIFF_PLANT");

    public static void main(String[] argv) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8), 1 << 20);
        PrintStream out = new PrintStream(System.out, false, "UTF-8");
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) continue;
            long t0 = System.nanoTime();
            String res;
            try {
                res = run(line.split("\t", -1));
            } catch (Throwable t) {
                res = "{\"driver_error\":" + js(String.valueOf(t)) + "}";
            }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            res = res.substring(0, res.length() - 1) + ",\"ms\":" + ms + "}";
            out.println(res);
            out.flush();
        }
    }

    static String field(String f) {
        if (f.equals("~")) return null;
        byte[] b = new byte[f.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(f.substring(2 * i, 2 * i + 2), 16);
        return new String(b, StandardCharsets.UTF_8);
    }

    static String run(String[] f) {
        String cmd = f[0];
        String base = field(f[1]) == null ? "" : field(f[1]);
        String token = field(f[2]) == null ? "" : field(f[2]);
        int timeoutMs = Integer.parseInt(f[3]);
        String[] a = new String[Math.max(0, f.length - 4)];
        for (int i = 0; i < a.length; i++) a[i] = field(f[4 + i]);
        Duration timeout = timeoutMs > 0 ? Duration.ofMillis(timeoutMs) : Duration.ofSeconds(30);
        if (cmd.equals("construct")) {
            try {
                new KeyorixClient(base, "x");
                return "{\"ok\":true,\"value\":{\"accepted\":true}}";
            } catch (Throwable e) {
                return fail(e, "validation");
            }
        }
        if (cmd.equals("login")) {
            try {
                String tok = Keyorix.login(base, a[0], a[1], timeout);
                return "{\"ok\":true,\"value\":{\"token_len\":" + (tok == null ? 0 : tok.length()) + "}}";
            } catch (Throwable e) {
                return fail(e, null);
            }
        }
        KeyorixClient c;
        try {
            c = new KeyorixClient(base, token, timeout);
        } catch (Throwable e) {
            return fail(e, "validation");
        }
        try {
            switch (cmd) {
                case "health":
                    return "{\"ok\":true,\"value\":" + c.health() + "}";
                case "list_secrets": {
                    String env = a[0];
                    if (PLANT.equals("P6") && env != null) env = Normalizer.normalize(env, Normalizer.Form.NFD);
                    return "{\"ok\":true,\"value\":" + secretList(c.listSecretsScoped("alpha", env)) + "}";
                }
                case "get_secret": {
                    String env = a[1];
                    if (PLANT.equals("P6") && env != null) env = Normalizer.normalize(env, Normalizer.Form.NFD);
                    return "{\"ok\":true,\"value\":" + js(c.getSecretScoped(a[0], "alpha", env)) + "}";
                }
                case "get_secret_in": {
                    String nm = a[2];
                    if (PLANT.equals("P6b") && nm != null) nm = Normalizer.normalize(nm, Normalizer.Form.NFD);
                    return "{\"ok\":true,\"value\":" + js(c.getSecretIn(a[0], a[1], nm)) + "}";
                }
                case "get_secret_by_ref":
                    return "{\"ok\":true,\"value\":" + js(c.getSecretByRef(a[0])) + "}";
                case "list_deleted_secrets": {
                    if (a[0] == null || !a[0].matches("[0-9]{1,9}")) return "{\"na\":true}";
                    return "{\"ok\":true,\"value\":" + secretList(c.listDeletedSecrets(Long.parseLong(a[0]))) + "}";
                }
                case "list_projects": {
                    StringBuilder sb = new StringBuilder("{\"ok\":true,\"value\":[");
                    List<com.keyorix.Project> l = c.listProjects();
                    for (int i = 0; i < l.size(); i++) {
                        com.keyorix.Project p = l.get(i);
                        if (i > 0) sb.append(',');
                        sb.append("{\"id\":").append(p.getId()).append(",\"name\":").append(js(p.getName()))
                          .append(",\"description\":").append(js(p.getDescription()))
                          .append(",\"created_at\":").append(js(p.getCreatedAt())).append('}');
                    }
                    return sb.append("]}").toString();
                }
                case "list_environments": {
                    if (a[0] == null || !a[0].matches("[0-9]{1,18}")) return "{\"na\":true}";
                    StringBuilder sb = new StringBuilder("{\"ok\":true,\"value\":[");
                    List<com.keyorix.Environment> l = c.listEnvironments(Long.parseLong(a[0]));
                    for (int i = 0; i < l.size(); i++) {
                        com.keyorix.Environment e = l.get(i);
                        if (i > 0) sb.append(',');
                        sb.append("{\"id\":").append(e.getId()).append(",\"project_id\":").append(e.getProjectId())
                          .append(",\"name\":").append(js(e.getName())).append('}');
                    }
                    return sb.append("]}").toString();
                }
                case "create_project":
                    return "{\"na\":true}";
                default:
                    return "{\"driver_error\":" + js("unknown cmd " + cmd) + "}";
            }
        } catch (Throwable e) {
            return fail(e, null);
        }
    }

    static String fail(Throwable e, String force) {
        String cls = "other";
        Integer status = null;
        if (force != null) cls = force;
        else if (e instanceof AuthException) { cls = "auth"; status = ((KeyorixException) e).getStatusCode(); }
        else if (e instanceof SecretNotFoundException) cls = "not_found";
        else if (e instanceof KeyorixException) {
            KeyorixException ke = (KeyorixException) e;
            if (ke.getStatusCode() != null) { cls = "http"; status = ke.getStatusCode(); }
            else if (ke.getCause() instanceof SocketTimeoutException) cls = "timeout";
            else if (ke.getCause() != null) cls = "network";
        }
        return "{\"ok\":false,\"class\":" + js(cls) + ",\"status\":" + (status == null ? "null" : status.toString())
            + ",\"native\":" + js(e.getClass().getSimpleName()) + ",\"msg\":" + js(String.valueOf(e.getMessage())) + "}";
    }

        static String secretList(List<Secret> l) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < l.size(); i++) {
            Secret s = l.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(s.getId()).append(",\"name\":").append(js(s.getName()))
              .append(",\"type\":").append(js(s.getType())).append(",\"project_id\":").append(s.getProjectId())
              .append(",\"environment\":").append(js(s.getEnvironment()))
              .append(",\"created_at\":").append(js(s.getCreatedAt()))
              .append(",\"purge_at\":").append(js(s.getPurgeAt() == null ? "" : s.getPurgeAt())).append('}');
        }
        return sb.append(']').toString();
    }

    static String js(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '"' || ch == '\\') sb.append('\\').append(ch);
            else if (ch < 0x20 || ch >= 0x7f) sb.append(String.format("\\u%04x", (int) ch));
            else sb.append(ch);
        }
        return sb.append('"').toString();
    }
}
