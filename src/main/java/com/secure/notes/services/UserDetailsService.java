package com.secure.notes.services;

import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsService {
    @Transactional
    UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException;
}
