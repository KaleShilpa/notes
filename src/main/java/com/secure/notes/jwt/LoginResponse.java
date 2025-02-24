package com.secure.notes.jwt;

import java.util.List;

public class LoginResponse {
    private String username;
    private String jwtToken;
    private List<String> roles;

    public String getJwtToken() {
        return jwtToken;
    }

    public LoginResponse(List<String> roles, String jwtToken, String username) {
        this.roles = roles;
        this.jwtToken = jwtToken;
        this.username = username;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
