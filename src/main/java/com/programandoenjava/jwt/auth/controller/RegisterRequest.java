package com.programandoenjava.jwt.auth.controller;

public record RegisterRequest(
        String name,
        String email,
        String password
) {
}
