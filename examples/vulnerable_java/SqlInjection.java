// Example vulnerable Java code — CWE-89 SQL Injection.
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

public class SqlInjection {
    public static ResultSet lookupUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        // CWE-89: untrusted input concatenated into SQL
        String query = "SELECT * FROM users WHERE id = " + userId;
        return stmt.executeQuery(query);
    }

    public static void runCommand(String name) throws Exception {
        // CWE-78: shell command injection
        Runtime.getRuntime().exec("ping -c1 " + name);
    }
}
