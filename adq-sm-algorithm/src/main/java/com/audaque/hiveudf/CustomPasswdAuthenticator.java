package com.audaque.hiveudf;

import org.apache.hive.service.auth.*;

import java.util.*;

import org.apache.hadoop.conf.*;

import java.io.*;
import javax.security.sasl.*;

public class CustomPasswdAuthenticator implements PasswdAuthenticationProvider {
    private final Map<String, String> userPasswordMap;

    public CustomPasswdAuthenticator() {
        this.userPasswordMap = new HashMap<>();
        this.init();
    }

    private void init() {
        final Configuration conf = new Configuration();
        final String passwdFile = conf.get("hive.server2.custom.authentication.file", "/home/hcsds/bigdata/hive-3.1.2/conf/hive-passwd");
        try {
            final BufferedReader reader = new BufferedReader(new FileReader(passwdFile));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        final String[] parts = line.split(":", 2);
                        if (parts.length != 2) {
                            continue;
                        }
                        this.userPasswordMap.put(parts[0], parts[1]);
                    }
                }
                reader.close();
            } catch (Throwable t) {
                try {
                    reader.close();
                } catch (Throwable t2) {
                    t.addSuppressed(t2);
                }
                throw t;
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read password file: " + passwdFile, e);
        }
    }

    public void Authenticate(final String user, final String password) throws AuthenticationException {
        final String storedPassword = this.userPasswordMap.get(user);
        if (storedPassword == null || !storedPassword.equals(password)) {
            throw new AuthenticationException("Invalid username or password");
        }
    }
}
