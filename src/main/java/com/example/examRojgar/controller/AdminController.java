package com.example.examRojgar.controller;

import com.example.examRojgar.dto.AuthRequest;
import com.example.examRojgar.dto.AuthResponse;
import com.example.examRojgar.entity.UserData;
import com.example.examRojgar.enums.Role;
import com.example.examRojgar.repository.UserRepository;
import com.example.examRojgar.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthRequest request) {
        if (userRepository.findByUsernameAndRole(request.getUsername(), Role.ROLE_ADMIN).isPresent()) {
            return ResponseEntity.badRequest().body("User already exists");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Password cannot be empty");
        }
        UserData user = new UserData();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.ROLE_ADMIN);
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        String token = jwtUtil.generateToken(auth);
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
