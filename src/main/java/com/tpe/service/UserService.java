package com.tpe.service;

import com.tpe.controller.dto.RegisterRequest;
import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.UserRole;
import com.tpe.exception.ConflictException;
import com.tpe.exception.ResourceNotFoundException;
import com.tpe.repository.RoleRepository;
import com.tpe.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void reqisterUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUserName(registerRequest.getUserName())) {
            throw new ConflictException("girdiğiniz username kullanımda");

        }
        Role role =
                roleRepository.findByName(UserRole.ROLE_STUDENT).orElseThrow(
                        () -> new ResourceNotFoundException("Role bilgisi bulunamadı"));
        Set<Role> roles = new HashSet<>();
        roles.add(role);

        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setUserName(registerRequest.getUserName());
        user.setRoles(roles);
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        userRepository.save(user);
    }
}
