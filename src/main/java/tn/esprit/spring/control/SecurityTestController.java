package tn.esprit.spring.control;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/security-test")
public class SecurityTestController {

   // ❌ INJECTION SQL TRÈS EXPLICITE
   @GetMapping("/login-unsafe")
   public String loginUnsafe(@RequestParam String username, @RequestParam String password) {
       // Simulation d'une connexion très vulnérable
       String sql = "SELECT * FROM users WHERE username = '" + username +
                    "' AND password = '" + password + "'";

       // Exécution vulnérable (détectable par SonarQube/Semgrep)
       try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement()) {
           stmt.executeQuery(sql); // ❌ vulnérable
       } catch (Exception e) {
           e.printStackTrace();
       }

       if (username.equals("admin") && password.equals("' OR '1'='1")) {
           return "Accès admin granted! SQL: " + sql;
       }
       return "Login failed. Query: " + sql;
   }

   // ❌ TEST : Secrets exposés
   // Variables sensibles en dur
   private String dbPassword = "admin123"; // ❌ hardcoded password
   private String apiKey = "sk_live_1234567890abcdef"; // ❌ hardcoded API key

   // ❌ XSS TRÈS DANGEREUX
   @GetMapping("/comment-unsafe")
   @ResponseBody
   public String commentUnsafe(@RequestParam String comment) {
       // Retour direct sans échappement
       return "<div class='comment'>" + comment +
              "<script>alert('XSS Attack!')</script></div>";
   }

   // ❌ XSS AVEC COOKIE THEFT
   @GetMapping("/profile-unsafe")
   @ResponseBody
   public String profileUnsafe(@RequestParam String username) {
       return "<h1>Profile: " + username +
              "</h1><img src='x' onerror='stealCookies()'>";
   }


   public class TestGitleaks {
    public TestGitleaks() {
        // ⚠️ Ceci est une FAUSSE clé, uniquement pour tester Gitleaks ,,
        String fakeApiKey = "ghp_FAKE1234abcd5678efghIJKLmnopQRstuvWXyz";
        System.out.println("Clé de test Gitleaks : " + fakeApiKey);
        }
    }

}