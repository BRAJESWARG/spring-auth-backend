package com.example.auth.service;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    // REGISTER user
    public User register(User user) {

        // Check if email already exists
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("User already exists!");
        }

        User u = new User();

        // Fix: username MUST NOT be null
        if (user.getUsername() != null && !user.getUsername().isEmpty()) {
            u.setUsername(user.getUsername());
        } else {
            u.setUsername(user.getEmail().split("@")[0]);  // auto-generate username
        }

        u.setEmail(user.getEmail());
        u.setPassword(passwordEncoder.encode(user.getPassword()));
        u.setRole("USER");

        return userRepository.save(u);
    }

    // LOGIN user
    public String login(String email, String rawPassword) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        // validate password
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        // return JWT token
        return jwtUtil.generateToken(user.getEmail());
    }
}
