package com.programandoenjava.jwt.auth.controller;

public record AuthRequest(
        String email,
        String password
) {
}
